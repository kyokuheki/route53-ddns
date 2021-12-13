import boto3
import hashlib
import ipaddress
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# For your security, use AWS Secrets Manager to store DK, salt, and ROLE ARN.
SALT = os.environ.get('SALT')
DK = os.environ.get('DK')
ROLE_ARN = os.environ.get('ROLE_ARN')

class DdnsException(Exception):
    def __init__(self, statusCode, message=""):
        self.statusCode = statusCode
        self.message = message
    def response(self):
        return {
            'statusCode': self.statusCode,
            'body': json.dumps({'errors':{'code': self.statusCode, 'message':self.message}})
        }

def get_client():
    if ROLE_ARN is not None:
        sts_connection = boto3.client('sts')
        account = sts_connection.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName="ddns"
        )
        return boto3.client('route53',
            aws_access_key_id=account['Credentials']['AccessKeyId'],
            aws_secret_access_key=account['Credentials']['SecretAccessKey'],
            aws_session_token=account['Credentials']['SessionToken'],)
    else:
        return boto3.client('route53')

def get_query_parameter(event, key,):
    try:
        r = event['queryStringParameters'][key]
        logger.info('{}: {}'.format(key, r))
    except Exception as e:
        logger.warn("{} not found.".format(key))
        raise DdnsException(statusCode=400, message="invalid query parameter: {} not found".format(key))
    return r

def route53_ddns(client, zone_id, resource_record_sets, fqdn, rtype, current_address):
    response = {'updated': False, 'new':current_address}
    target_rr = [v for v in resource_record_sets if v['Type'] == rtype]
    logger.info(target_rr)
    
    if len(target_rr):
        registered_address = target_rr[0]['ResourceRecords'][0]['Value']
        response['old'] = registered_address
        logger.info('new: {}\nold: {}'.format(current_address, registered_address))
        if current_address != registered_address:
            logger.info('ddns update required: ({}: {})'.format(fqdn, rtype))
            target_rr[0]['ResourceRecords'][0]['Value'] = current_address
            client.change_resource_record_sets(
                HostedZoneId = zone_id,
                ChangeBatch = {
                    'Comment': 'ddns update',
                    'Changes': [{
                        'Action': 'UPSERT',
                        'ResourceRecordSet':target_rr[0]
                    }]
                }
            )
            logger.info('ddns updated: ({}: {})'.format(fqdn, rtype))
            response['updated'] = True
    elif resource_record_sets != []:
        response['error'] = "The requested record type({}) does not exist in ResourceRecords({}): {}".format(rtype, fqdn, resource_record_sets)
    else:
        response['error'] = "ResourceRecords({}) is unregistered.".format(fqdn)
    return response

def lambda_handler(event, context):
    response = {}
    try:
        if DK != hashlib.sha256((SALT + get_query_parameter(event, 'key')).encode()).hexdigest():
            raise DdnsException(statusCode=403, message="Bad Authentication data.")
        source_ip = event['requestContext']['http']['sourceIp']
        logger.info('source_ip: {}'.format(source_ip))
        fqdn = get_query_parameter(event, 'fqdn')
        zone_id = get_query_parameter(event, 'zone_id')
        
        # register the value of ipv4_addr if it is a valid value, or the source IPv4 address if it is 'source'.
        try:
            current_address_v4 = get_query_parameter(event, 'ipv4_addr')
            ipv4_enabled = True
        except DdnsException:
            ipv4_enabled = False
        else:
            try:
                current_address_v4 = str(ipaddress.IPv4Address(current_address_v4))
            except ipaddress.AddressValueError:
                if current_address_v4 == 'source':
                    current_address_v4 = source_ip
                else:
                    raise DdnsException(statusCode=400, message="ipv4_addr is invalid.")
        
        # register the value of ipv6_addr if it is a valid value.
        try:
            current_address_v6 = str(ipaddress.IPv6Address(get_query_parameter(event, 'ipv6_addr')))
            ipv6_enabled = True
        except ipaddress.AddressValueError:
            raise DdnsException(statusCode=400, message="ipv6_addr is invalid.")
        except DdnsException:
            ipv6_enabled = False
        
        if not ipv4_enabled and not ipv6_enabled:
            raise DdnsException(statusCode=400, message="Both ipv4_addr and ipv6_addr are missing or invalid values.")
        
        # get client
        client = get_client()
        resource_record_sets = [v for v in client.list_resource_record_sets(HostedZoneId=zone_id)['ResourceRecordSets'] if v['Name'] == fqdn]

        # register IPv4 address
        if ipv4_enabled:
            response['ipv4'] = route53_ddns(client, zone_id, resource_record_sets, fqdn, 'A', current_address_v4)

        # register IPv6 address
        if ipv6_enabled:
            response['ipv6'] = route53_ddns(client, zone_id, resource_record_sets, fqdn, 'AAAA', current_address_v6)

    except DdnsException as e:
        logger.exception(e.message)
        return e.response()
    except Exception as e:
        logger.exception("An unknown exception has occurred.")
        import traceback
        return {
            'statusCode': 500,
            'body': json.dumps({'errors':{'code': 500, 'message':str(e) + traceback.format_exc()}})
        }
    return {'statusCode': 200, 'body': json.dumps(response)}
