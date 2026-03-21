import os
import boto3
from botocore.exceptions import ClientError

endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:5000")
region = "us-east-1"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = region

print(f"Semeando recursos vulneráveis EXTREMOS no ambiente simulado ({endpoint_url})...")

try:
    s3 = boto3.client('s3', region_name=region, endpoint_url=endpoint_url)
    s3.create_bucket(Bucket='vazamento-dados-clientes')
    s3.put_public_access_block(
        Bucket='vazamento-dados-clientes',
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': False, 'IgnorePublicAcls': False,
            'BlockPublicPolicy': False, 'RestrictPublicBuckets': False
        }
    )
    s3.create_bucket(Bucket='backup-sem-criptografia-logs')
    # Intencionalmente sem policy de Lifecycle
except Exception as e: print("S3 error:", e)

try:
    ec2 = boto3.client('ec2', region_name=region, endpoint_url=endpoint_url)
    vpcs = ec2.describe_vpcs()
    vpc_id = vpcs['Vpcs'][0]['VpcId'] if vpcs.get('Vpcs') else ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']
    sn_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24')['Subnet']['SubnetId']
    
    sg = ec2.create_security_group(GroupName='sg-admin-aberto-v2', Description='acesso', VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ]
    )
    
    # Gerando Geração Antiga: m4.large
    ins = ec2.run_instances(ImageId='ami-12345678', MinCount=1, MaxCount=1, InstanceType='m4.large', SubnetId=sn_id)
    ec2.stop_instances(InstanceIds=[ins['Instances'][0]['InstanceId']])
    
    # Volumes não criptografados
    for _ in range(3): ec2.create_volume(AvailabilityZone='us-east-1a', Size=200, VolumeType='gp2', Encrypted=False)
    
    # EIPs e NAT Gateway
    eip = ec2.allocate_address(Domain='vpc')
    ec2.allocate_address(Domain='vpc')
    ec2.create_nat_gateway(SubnetId=sn_id, AllocationId=eip['AllocationId'])
    
    # Snapshot EBS
    vol = ec2.create_volume(AvailabilityZone='us-east-1a', Size=500, VolumeType='gp2')
    ec2.create_snapshot(VolumeId=vol['VolumeId'], Description="Snapshot antigo gerado pelo mock")

except Exception as e: print("EC2 error:", e)

try:
    iam = boto3.client('iam', region_name=region, endpoint_url=endpoint_url)
    for u in ['dev-joao', 'admin-master']: 
        iam.create_user(UserName=u)
        iam.create_access_key(UserName=u) # Criando keys pra auditoria >90d
except Exception as e: print("IAM error:", e)

try:
    rds = boto3.client('rds', region_name=region, endpoint_url=endpoint_url)
    rds.create_db_instance(
        DBInstanceIdentifier='db-abandono-publico',
        AllocatedStorage=500,
        DBInstanceClass='db.m4.large', # m4 is ancient!
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='pwd',
        PubliclyAccessible=True,
        StorageEncrypted=False
    )
except Exception as e: print("RDS error:", e)

try:
    dynamo = boto3.client('dynamodb', region_name=region, endpoint_url=endpoint_url)
    dynamo.create_table(
        TableName='tabela-fantasmas-v2',
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        ProvisionedThroughput={'ReadCapacityUnits': 100, 'WriteCapacityUnits': 100}
    )
except Exception as e: print("DynamoDB error:", e)

print("Ambiente configurado com VULNERABILIDADES AVANÇADAS!")
