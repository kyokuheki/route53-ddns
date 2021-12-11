import boto3
import hashlib
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# For your security, use AWS Secrets Manager to store DK, salt, and ROLE ARN.
SALT = os.environ.get('SALT')
DK = os.environ.get('DK').encode()
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

def checkkey(s: str):
    return DK == hashlib.sha256((SALT + s).encode()).hexdigest()

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

def get_query_parameter(event, key):
    try:
        r = event['queryStringParameters'][key]
        logger.info('{}: {}'.format(key, r))
    except Exception as e:
        logging.exception("{} not found.".format(key))
        raise DdnsException(statusCode=400, message="invalid query parameter: {} not found".format(key))
    return r

def lambda_handler(event, context):
    try:
        if checkkey(get_query_parameter(event, 'key')):
            raise DdnsException(statusCode=403, message="Bad Authentication data.")
        source_ip = event['requestContext']['http']['sourceIp']
        logger.info('source_ip: {}'.format(source_ip))
        ipver = get_query_parameter(event, 'ipver')
        fqdn = get_query_parameter(event, 'fqdn')
        zone_id = get_query_parameter(event, 'zone_id')
        
        if ipver == '4':
            current_address = source_ip
            rtype = "A"
        elif ipver == '6':
            current_address = get_query_parameter(event, 'ipv6')
            rtype = "AAAA"
        else:
            raise DdnsException(statusCode=400, message="invalid ipver.")
        
        client = get_client()
        response = client.list_resource_record_sets(HostedZoneId=zone_id)
         
        rrecords = [v for v in response['ResourceRecordSets'] if v['Name'] == fqdn]
        target_rrecord = [v for v in rrecords if v['Type'] == rtype]
        logger.info(target_rrecord)
        
        if len(target_rrecord):
            registered_address = target_rrecord[0]['ResourceRecords'][0]['Value']
        elif rrecords != []:
            raise DdnsException(statusCode=409, message="ResourceRecords({}) is not sutable: {}".format(fqdn, rrecords))
        else:
            raise DdnsException(statusCode=409, message="ResourceRecords({}) is unregistered.".format(fqdn))
        
        logger.info('current_address: {}'.format(current_address))
        logger.info('registered_address: {}'.format(registered_address))

        if current_address != registered_address:
            logger.info('ddns update required')
            target_rrecord[0]['ResourceRecords'][0]['Value'] = current_address
            client.change_resource_record_sets(
                HostedZoneId = zone_id,
                ChangeBatch = {
                    'Comment': 'ddns update',
                    'Changes': [{
                        'Action': 'UPSERT',
                        'ResourceRecordSet':target_rrecord[0]
                    }]
                }
            )
            updated = True
            logger.info('ddns updated')
        else:
            updated = False
    except DdnsException as e:
        return e.response()
    except Exception as e:
        logging.exception("an unknown exception has occurred.")
        import traceback
        return {
            'statusCode': 500,
            'body': json.dumps({'errors':{'code': 500, 'message':str(e) + traceback.format_exc()}})
        }
        
    return {
        'statusCode': 200,
        'body': json.dumps({'ipver':ipver, 'type':rtype, 'updated': updated, 'new':current_address, 'old':registered_address})
    }
