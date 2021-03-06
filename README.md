# route53-ddns
DDNS with AWS Lambda, Amazon API Gateway and Route53

## Role
- role: ddns-role
  - description: delegate access across AWS accounts
  - policy: [policy-route53.yaml](policy-route53.yaml)
- role: lambda-ddns-role
  - description: A role for Lambda to access cross-account route53. 
  - policy:
    - [policy-assume-role.yaml](./policy-assume-role.yaml)
    - AWSLambdaBasicExecutionRole: A role automatically generated by AWS

## Lambda
- role: lambda-ddns-role
- code: [lambda_function.py](./lambda_function.py)
- trigger
  - API Gateway
    - protocol: HTTP
- environment variables
  - DK: sha256(SALT+key)
    - `hashlib.sha256((SALT + key).encode()).hexdigest()`
  - SALT: Random string to set for SALT
  - ROLE_ARN: ARN of ddns-role. If you do not want cross-account access, do not set it.

## curl

```shell
# IPv6/IPv4
curl -X POST 'https://XXXXXXXXXXX.execute-api.ap-northeast-1.amazonaws.com/default/ddns?zone_id=<YOUR_HOSTED_ZONE_ID>&key=<key>&fqdn=<example.com.>&ipv6=<IPV6_ADDRESS>&ipv6=<IPV4_ADDRESS>'

# IPv6
curl -X POST 'https://XXXXXXXXXXX.execute-api.ap-northeast-1.amazonaws.com/default/ddns?zone_id=<YOUR_HOSTED_ZONE_ID>&key=<key>&fqdn=<v6.example.com.>&ipv6=<IPV6_ADDRESS>'

# IPv4
curl -X POST 'https://XXXXXXXXXXX.execute-api.ap-northeast-1.amazonaws.com/default/ddns?zone_id=<YOUR_HOSTED_ZONE_ID>&key=<key>&fqdn=<v4.example.com.>&ipv4=<IPV4_ADDRESS>'
## if ipv4=source, register the source IP address.
curl -X POST 'https://XXXXXXXXXXX.execute-api.ap-northeast-1.amazonaws.com/default/ddns?zone_id=<YOUR_HOSTED_ZONE_ID>&key=<key>&fqdn=<v4.example.com.>&ipv4=source'
```

## refs
- https://orange.kaosy.org/2021/04/05/dynamic-dns-using-route-53-and-lambda/
- https://www.rocher.kyoto.jp/arbr/?p=1460
- https://qiita.com/nori3tsu/items/80a620553f589e19f002
- https://qiita.com/keys/items/43adf968d366e80f0003
- https://aws.amazon.com/jp/blogs/compute/building-a-dynamic-dns-for-route-53-using-cloudwatch-events-and-lambda/
