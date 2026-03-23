import streamlit as st
import pandas as pd
import boto3
import os
import uuid
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Importando os modelos que definimos para o banco de dados
from models import Base, Scan, Tenant

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(page_title="Cloud Auditor - CSPM & FinOps", page_icon="🛡️", layout="wide")

CUSTOM_CSS = """
<style>
    /* Aplicação avançada da paleta: FF7533, 8445CC, 2A2A2A, 000000 */
    .stApp {
        background-color: #000000;
    }
    
    [data-testid="stSidebar"] {
        background-color: #0a0a0a;
        border-right: 1px solid #2A2A2A;
    }

    /* Cards de KPI (Métricas) */
    div[data-testid="metric-container"] {
        background-color: #111111;
        background-image: linear-gradient(135deg, rgba(255,117,51,0.08) 0%, rgba(132,69,204,0.08) 100%);
        border: 1px solid #2A2A2A;
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.6);
        transition: transform 0.3s ease, border-color 0.3s ease;
    }
    
    div[data-testid="metric-container"]:hover {
        transform: translateY(-5px);
        border-color: #FF7533;
    }

    div[data-testid="stMetricLabel"] > div > div {
        color: #A0A0A0;
        font-size: 1.1rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    div[data-testid="stMetricValue"] {
        background: -webkit-linear-gradient(45deg, #FF7533, #8445CC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.8rem !important;
        font-weight: 800;
        padding-top: 10px;
    }

    div[data-testid="stMetricDelta"] svg {
        fill: #8445CC;
    }

    /* Abas */
    .stTabs [data-baseweb="tab-list"] {
        gap: 15px;
        background-color: transparent;
    }

    .stTabs [data-baseweb="tab"] {
        background-color: #111111;
        border: 1px solid #2A2A2A;
        border-bottom: none;
        border-radius: 10px 10px 0px 0px;
        padding: 12px 24px;
        color: #A0A0A0;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(90deg, #FF7533, #8445CC);
        color: #FFFFFF !important;
        border: none;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background-color: #111111;
        border: 1px solid #2A2A2A;
        border-radius: 10px;
        margin-bottom: 12px;
    }
    
    [data-testid="stExpander"] summary {
        color: #FFFFFF;
        font-weight: 600;
    }
    
    [data-testid="stExpander"] summary:hover {
        color: #FF7533;
    }

    /* Botões */
    .stButton > button {
        background: linear-gradient(45deg, #8445CC, #FF7533);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: bold;
        transition: opacity 0.3s;
        height: 45px;
        width: 100%;
    }
    .stButton > button:hover {
        opacity: 0.85;
        color: white;
    }
    
    /* Header Gradient */
    h1 {
        background: -webkit-linear-gradient(45deg, #FF7533, #8445CC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Variáveis de Ambiente e AWS
AWS_ENDPOINT = os.getenv("AWS_ENDPOINT_URL")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/data/cloudauditor.db")


def _boto_client(service):
    return boto3.client(service, endpoint_url=AWS_ENDPOINT, region_name=AWS_REGION)


def get_all_paginated_items(client, method_name, list_key, **kwargs):
    """Retorna todos os itens de uma API paginada do Boto3."""
    try:
        paginator = client.get_paginator(method_name)
        all_items = []
        for page in paginator.paginate(**kwargs):
            all_items.extend(page.get(list_key, []))
        return all_items
    except Exception as e:
        st.warning(f"Paginação falhou para {method_name}: {e}")
        return []

# --- CONFIGURAÇÃO DO BANCO DE DADOS (SQLALCHEMY) ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Cria as tabelas no banco de dados se elas não existirem
Base.metadata.create_all(bind=engine)

# --- FUNÇÕES AUXILIARES DE BANCO ---
def save_audit_to_db(account_id, finops_data, sec_data, economy_total):
    db = SessionLocal()
    try:
        # Busca ou cria o Tenant (Cliente) baseado na conta AWS auditada
        tenant = db.query(Tenant).filter(Tenant.aws_account_id == account_id).first()
        if not tenant:
            tenant = Tenant(name="Cliente Padrão", aws_account_id=account_id)
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        # Cálculo de Score: Base 100, desconta 5 pontos por alerta encontrado
        total_alerts = len(finops_data) + len(sec_data)
        current_score = max(0, 100 - (total_alerts * 5))

        new_scan = Scan(
            tenant_id=tenant.id,
            score=current_score,
            findings={
                "finops": finops_data,
                "security": sec_data,
                "savings_projected": economy_total
            }
        )
        db.add(new_scan)
        db.commit()
        return True
    except Exception as e:
        st.sidebar.error(f"Erro ao persistir no banco: {e}")
        return False
    finally:
        db.close()

# --- FUNÇÕES DE AUDITORIA (LOGICA ORIGINAL) ---
def get_aws_account_id():
    sts = _boto_client('sts')
    return sts.get_caller_identity()["Account"]

# ---------------------------------------------------------------------------
# FUNÇÕES DE FINOPS
# ---------------------------------------------------------------------------

def audit_ebs_volumes():
    """EBS volumes disponíveis (não anexados) — paginated."""
    ec2 = _boto_client('ec2')
    volumes = get_all_paginated_items(
        ec2, 'describe_volumes', 'Volumes',
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    resultados = []
    for v in volumes:
        custo_mensal = v['Size'] * 0.08
        resultados.append({
            'Serviço': 'EBS',
            'ID do Recurso': v['VolumeId'],
            'Detalhe': f"{v['Size']} GB ({v['VolumeType']}) — disponível sem uso",
            'Economia Mensal Estimada': custo_mensal
        })
    return resultados


def audit_elastic_ips():
    """Elastic IPs não associados."""
    ec2 = _boto_client('ec2')
    ips = ec2.describe_addresses()
    resultados = []
    for ip in ips.get('Addresses', []):
        if 'AssociationId' not in ip:
            resultados.append({
                'Serviço': 'EC2 / EIP',
                'ID do Recurso': ip['PublicIp'],
                'Detalhe': 'Elastic IP não associado a nenhum recurso',
                'Economia Mensal Estimada': 3.60
            })
    return resultados

def audit_ec2_stopped():
    """EC2 paradas ainda pagando pelos volumes EBS anexados."""
    ec2 = _boto_client('ec2')
    reservations = get_all_paginated_items(
        ec2, 'describe_instances', 'Reservations',
        Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
    )
    resultados = []
    for reservation in reservations:
        for instance in reservation.get('Instances', []):
            # describe_instances does not return VolumeSize — must call describe_volumes
            volume_ids = [
                bdm['Ebs']['VolumeId']
                for bdm in instance.get('BlockDeviceMappings', [])
                if 'Ebs' in bdm and 'VolumeId' in bdm['Ebs']
            ]
            total_ebs_gb = 0
            if volume_ids:
                try:
                    vols = ec2.describe_volumes(VolumeIds=volume_ids)
                    total_ebs_gb = sum(v.get('Size', 0) for v in vols.get('Volumes', []))
                except Exception:
                    pass
            custo_mensal = total_ebs_gb * 0.10
            tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
            nome = tags.get('Name', instance['InstanceId'])
            resultados.append({
                'Serviço': 'EC2 Parada',
                'ID do Recurso': instance['InstanceId'],
                'Detalhe': f"{nome} | {instance['InstanceType']} | EBS estimado: {total_ebs_gb} GB",
                'Economia Mensal Estimada': custo_mensal
            })
    return resultados


def audit_lambda_functions():
    """Funções Lambda ociosas (sem invocação há mais de 90 dias) ou com memória excessiva (>= 1024 MB)."""
    lambda_client = _boto_client('lambda')
    functions = get_all_paginated_items(lambda_client, 'list_functions', 'Functions')
    resultados = []
    now = datetime.now(timezone.utc)
    for func in functions:
        memory_mb = func.get('MemorySize', 128)
        last_modified_str = func.get('LastModified', '')
        idle = False
        days_idle = None

        try:
            # LastModified formato: "2024-01-15T10:30:00.000+0000"
            last_modified = datetime.fromisoformat(last_modified_str.replace('+0000', '+00:00'))
            days_idle = (now - last_modified).days
            idle = days_idle > 90
        except Exception:
            pass

        oversized = memory_mb >= 1024

        if idle or oversized:
            motivo = []
            if idle:
                motivo.append(f"sem modificação há {days_idle} dias")
            if oversized:
                motivo.append(f"memória de {memory_mb} MB (verifique rightsizing)")
            # Estimativa conservadora: ~$0.20/mês por função ociosa de alta memória
            custo_estimado = (memory_mb / 1024) * 0.20 if oversized else 0.10
            resultados.append({
                'Serviço': 'Lambda',
                'ID do Recurso': func['FunctionName'],
                'Detalhe': ' | '.join(motivo),
                'Economia Mensal Estimada': round(custo_estimado, 2)
            })
    return resultados


def audit_rds_instances():
    """Instâncias RDS paradas — ainda cobram armazenamento e snapshots."""
    rds = _boto_client('rds')
    db_instances = get_all_paginated_items(rds, 'describe_db_instances', 'DBInstances')
    resultados = []
    for db in db_instances:
        status = db.get('DBInstanceStatus', '')
        if status == 'stopped':
            # Estimativa: $0.115/GB-mês (gp2) para armazenamento alocado
            storage_gb = db.get('AllocatedStorage', 0)
            custo_mensal = storage_gb * 0.115
            resultados.append({
                'Serviço': 'RDS',
                'ID do Recurso': db['DBInstanceIdentifier'],
                'Detalhe': (
                    f"{db['Engine']} {db.get('EngineVersion', '')} | "
                    f"{db['DBInstanceClass']} | {storage_gb} GB alocado | parada"
                ),
                'Economia Mensal Estimada': round(custo_mensal, 2)
            })
    return resultados


def audit_dynamodb_tables():
    """Tabelas DynamoDB com throughput provisionado e baixa utilização (ItemCount = 0)."""
    dynamodb = _boto_client('dynamodb')
    table_names = get_all_paginated_items(dynamodb, 'list_tables', 'TableNames')
    resultados = []
    for table_name in table_names:
        try:
            desc = dynamodb.describe_table(TableName=table_name)['Table']
            billing = desc.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
            item_count = desc.get('ItemCount', 0)
            rcu = desc.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0)
            wcu = desc.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0)

            if billing == 'PROVISIONED' and item_count == 0 and (rcu > 0 or wcu > 0):
                # Estimativa: $0.00065/WCU-hora + $0.00013/RCU-hora × 730 horas
                custo_mensal = ((wcu * 0.00065) + (rcu * 0.00013)) * 730
                resultados.append({
                    'Serviço': 'DynamoDB',
                    'ID do Recurso': table_name,
                    'Detalhe': (
                        f"Provisionado | {rcu} RCU / {wcu} WCU | "
                        f"0 itens — considere On-Demand ou exclusão"
                    ),
                    'Economia Mensal Estimada': round(custo_mensal, 2)
                })
        except Exception:
            pass
    return resultados


def audit_load_balancers():
    """ALBs/NLBs provisionados — custo fixo de ~$5.76/mês mesmo sem tráfego."""
    elbv2 = _boto_client('elbv2')
    lbs = get_all_paginated_items(elbv2, 'describe_load_balancers', 'LoadBalancers')
    resultados = []
    for lb in lbs:
        # Verifica se tem target groups com alvos saudáveis
        try:
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
            target_groups = tgs.get('TargetGroups', [])
            total_targets = 0
            for tg in target_groups:
                health = elbv2.describe_target_health(
                    TargetGroupArn=tg['TargetGroupArn']
                )
                total_targets += len(health.get('TargetHealthDescriptions', []))

            if total_targets == 0:
                resultados.append({
                    'Serviço': f"LB ({lb['Type'].upper()})",
                    'ID do Recurso': lb['LoadBalancerName'],
                    'Detalhe': f"{lb['Scheme']} | sem targets saudáveis registrados",
                    'Economia Mensal Estimada': 5.76
                })
        except Exception:
            pass
    return resultados


def audit_old_snapshots():
    """Snapshots EBS antigos sem volume associado (> 90 dias)."""
    ec2 = _boto_client('ec2')
    sts = _boto_client('sts')
    try:
        account_id = sts.get_caller_identity()["Account"]
        snapshots = get_all_paginated_items(ec2, 'describe_snapshots', 'Snapshots', OwnerIds=[account_id])
    except Exception:
        snapshots = []
    
    resultados = []
    now = datetime.now(timezone.utc)
    for snap in snapshots:
        start_time = snap.get('StartTime')
        if start_time and (now - start_time).days > 90:
            vol_size = snap.get('VolumeSize', 0)
            custo = vol_size * 0.05  # Aprox $0.05/GB-mês EBS Snapshot
            resultados.append({
                'Serviço': 'EBS Snapshot',
                'ID do Recurso': snap['SnapshotId'],
                'Detalhe': f"Snapshot de {vol_size}GB com mais de 90 dias",
                'Economia Mensal Estimada': round(custo, 2)
            })
    return resultados


def audit_nat_gateways():
    """NAT Gateways provisionados com baixo/nenhum tráfego."""
    ec2 = _boto_client('ec2')
    try:
        nats = get_all_paginated_items(ec2, 'describe_nat_gateways', 'NatGateways')
    except Exception:
        nats = []
    resultados = []
    for nat in nats:
        if nat.get('State') == 'available':
            resultados.append({
                'Serviço': 'NAT Gateway',
                'ID do Recurso': nat['NatGatewayId'],
                'Detalhe': 'Ocioso ou ativo faturando por hora',
                'Economia Mensal Estimada': 32.00 # Aprox mensal fixo minimum
            })
    return resultados


def audit_s3_lifecycle():
    """Buckets sem regras de ciclo de vida ativas."""
    s3 = _boto_client('s3')
    try:
        buckets = s3.list_buckets().get('Buckets', [])
    except Exception:
        buckets = []
        
    resultados = []
    for b in buckets:
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=b['Name'])
        except ClientError as e:
            if 'NoSuchLifecycleConfiguration' in str(e):
                resultados.append({
                    'Serviço': 'S3 Lifecycle',
                    'ID do Recurso': b['Name'],
                    'Detalhe': 'Sem regra para transição de logs antigos para Glacier',
                    'Economia Mensal Estimada': 0.0  # Fica zerado por ser muito variavel
                })
    return resultados


def audit_old_generation():
    """Verifica EC2 de gerações muito antigas (t2, m4)."""
    ec2 = _boto_client('ec2')
    try:
        instances = get_all_paginated_items(ec2, 'describe_instances', 'Reservations')
    except Exception:
        instances = []
    resultados = []
    antigas = ['t2.', 'm4.', 'c4.', 'r4.']
    for r in instances:
        for i in r.get('Instances', []):
            itype = i.get('InstanceType', '')
            if any(itype.startswith(fam) for fam in antigas):
                resultados.append({
                    'Serviço': 'EC2 Geração Antiga',
                    'ID do Recurso': i['InstanceId'],
                    'Detalhe': f"Modernize {itype} para Graviton (t4g/m6g) para reduzir em até 20% o custo",
                    'Economia Mensal Estimada': 5.00 # Estimativa genérica
                })
    return resultados


# ---------------------------------------------------------------------------
# FUNÇÕES DE SEGURANÇA
# ---------------------------------------------------------------------------

def audit_s3_public_access():
    s3 = _boto_client('s3')
    buckets = s3.list_buckets()['Buckets']
    exposed_buckets = []
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            config = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
            if not (config.get('BlockPublicAcls') and config.get('BlockPublicPolicy')):
                exposed_buckets.append({
                    'ID do Recurso': bucket_name,
                    'Severidade': 'Alta',
                    'Risco': 'Bloqueio de acesso público incompleto (S3)'
                })
        except ClientError:
            exposed_buckets.append({
                'ID do Recurso': bucket_name,
                'Severidade': 'Crítica',
                'Risco': 'Sem política de bloqueio público configurada (S3)'
            })
    return exposed_buckets


def audit_security_groups():
    ec2 = _boto_client('ec2')
    sgs = get_all_paginated_items(ec2, 'describe_security_groups', 'SecurityGroups')
    risky_sgs = []
    for sg in sgs:
        for rule in sg.get('IpPermissions', []):
            port = rule.get('FromPort')
            if port in [22, 3389]:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        risky_sgs.append({
                            'ID do Recurso': sg['GroupId'],
                            'Severidade': 'Crítica',
                            'Risco': f"Porta {port} aberta para a internet (0.0.0.0/0)"
                        })
                for ip_range in rule.get('Ipv6Ranges', []):
                    if ip_range.get('CidrIpv6') == '::/0':
                        risky_sgs.append({
                            'ID do Recurso': sg['GroupId'],
                            'Severidade': 'Crítica',
                            'Risco': f"Porta {port} aberta para a internet (::/0 IPv6)"
                        })
    return risky_sgs


def audit_s3_encryption():
    """Buckets sem criptografia padrão habilitada (SSE)."""
    s3 = _boto_client('s3')
    buckets = s3.list_buckets()['Buckets']
    resultados = []
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                resultados.append({
                    'ID do Recurso': bucket_name,
                    'Severidade': 'Média',
                    'Risco': 'Criptografia SSE não habilitada no bucket S3'
                })
    return resultados


def audit_iam_users_no_mfa():
    """Usuários IAM sem MFA habilitado."""
    iam = _boto_client('iam')
    users = get_all_paginated_items(iam, 'list_users', 'Users')
    resultados = []
    for user in users:
        try:
            mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices.get('MFADevices'):
                resultados.append({
                    'ID do Recurso': user['UserName'],
                    'Severidade': 'Alta',
                    'Risco': 'Usuário IAM sem MFA habilitado'
                })
        except Exception:
            pass
    return resultados


def audit_iam_old_keys():
    """Access Keys não rotacionadas há >90 dias."""
    iam = _boto_client('iam')
    try:
        users = get_all_paginated_items(iam, 'list_users', 'Users')
    except Exception:
        return []
    resultados = []
    now = datetime.now(timezone.utc)
    for u in users:
        try:
            keys = get_all_paginated_items(iam, 'list_access_keys', 'AccessKeyMetadata', UserName=u['UserName'])
            for k in keys:
                age = (now - k['CreateDate']).days
                if age > 90 and k['Status'] == 'Active':
                    resultados.append({
                        'ID do Recurso': f"{u['UserName']} / {k['AccessKeyId']}",
                        'Severidade': 'Crítica',
                        'Risco': f"Access Key rotacionada há {age} dias (>90) (A.9.2 ISO-27001)"
                    })
        except Exception:
            pass
    return resultados


def audit_rds_public():
    """RDS marcado como PubliclyAccessible = True."""
    rds = _boto_client('rds')
    try:
        db_instances = get_all_paginated_items(rds, 'describe_db_instances', 'DBInstances')
    except Exception:
        db_instances = []
    resultados = []
    for db in db_instances:
        if db.get('PubliclyAccessible', False):
            resultados.append({
                'ID do Recurso': db['DBInstanceIdentifier'],
                'Severidade': 'Crítica',
                'Risco': 'Banco RDS exposto publicamente para a internet'
            })
    return resultados


def audit_cloudtrail():
    """Verifica se CloudTrail não está capturando trilhas."""
    ct = _boto_client('cloudtrail')
    try:
        trails = ct.describe_trails()
        if not trails.get('trailList'):
            return [{
                'ID do Recurso': 'AWS Account',
                'Severidade': 'Alta',
                'Risco': 'Nenhum AWS CloudTrail configurado - falta de rastreio de auditoria'
            }]
    except Exception:
        pass
    return []


def audit_ebs_encryption():
    """Verifica Volumes EBS não encriptados."""
    ec2 = _boto_client('ec2')
    try:
        volumes = get_all_paginated_items(ec2, 'describe_volumes', 'Volumes')
    except Exception:
        return []
    resultados = []
    for v in volumes:
        if not v.get('Encrypted', False):
            resultados.append({
                'ID do Recurso': v['VolumeId'],
                'Severidade': 'Alta',
                'Risco': 'Volume EBS sem criptografia KMS nativa (A.10 ISO-27001)'
            })
    return resultados


# ---------------------------------------------------------------------------
# INTERFACE STREAMLIT
# ---------------------------------------------------------------------------

st.title("🛡️ Cloud Auditor CSPM & FinOps")
st.markdown(
    "Plataforma de Auditoria Contínua baseada em **ISO 27001** e redução de custos em nuvem."
)

try:
    account_id = get_aws_account_id()
    st.success(f"✅ Conectado com sucesso na conta AWS: **{account_id}**")

    with st.spinner("Coletando dados da AWS..."):
        # FinOps Clássico
        ebs_risks     = audit_ebs_volumes()
        eip_risks     = audit_elastic_ips()
        ec2_stopped   = audit_ec2_stopped()
        lambda_risks  = audit_lambda_functions()
        rds_risks     = audit_rds_instances()
        dynamo_risks  = audit_dynamodb_tables()
        lb_risks      = audit_load_balancers()
        
        # FinOps Avançado
        old_snaps     = audit_old_snapshots()
        nat_risks     = audit_nat_gateways()
        s3_cycle      = audit_s3_lifecycle()
        gen_risks     = audit_old_generation()

        # Segurança Clássica
        s3_risks      = audit_s3_public_access()
        sg_risks      = audit_security_groups()
        s3_enc_risks  = audit_s3_encryption()
        iam_mfa_risks = audit_iam_users_no_mfa()
        
        # Segurança Avançada
        iam_keys      = audit_iam_old_keys()
        rds_pub       = audit_rds_public()
        ct_risks      = audit_cloudtrail()
        ebs_enc_risks = audit_ebs_encryption()

    finops_data = ebs_risks + eip_risks + ec2_stopped + lambda_risks + rds_risks + dynamo_risks + lb_risks + old_snaps + nat_risks + s3_cycle + gen_risks
    sec_data    = s3_risks + sg_risks + s3_enc_risks + iam_mfa_risks + iam_keys + rds_pub + ct_risks + ebs_enc_risks

    economia_total_usd = sum(item.get('Economia Mensal Estimada', 0) for item in finops_data)
    total_finops_alertas = len(finops_data)
    total_sec_alertas = len(sec_data)

    # --- MÉTRICAS PRINCIPAIS ---
    col1, col2, col3 = st.columns(3)
    col1.metric("💰 Economia Potencial (Mês)", f"US$ {economia_total_usd:.2f}", delta="Redução Imediata")
    col2.metric("⚠️ Alertas de FinOps", total_finops_alertas, delta_color="inverse")
    col3.metric("🚨 Alertas de Segurança", total_sec_alertas, delta_color="inverse")

    st.divider()

    # --- ABAS PRINCIPAIS ---
    tab_finops, tab_sec, tab_exec = st.tabs([
        "💰 FinOps — Recursos Ociosos",
        "🔒 Segurança (CSPM / ISO 27001)",
        "📊 Resumo Executivo"
    ])

    # ---- TAB FINOPS ----
    with tab_finops:
        st.header("Recursos Gerando Custo Desnecessário")

        sections = [
            ("Snapshots Órfãos e Históricos (>90d)", old_snaps),
            ("NAT Gateways Provisionados", nat_risks),
            ("Modernização de Famílias EC2 Obsoletas", gen_risks),
            ("EBS Volumes Disponíveis", ebs_risks),
            ("Elastic IPs Ociosos", eip_risks),
            ("EC2 Paradas (EBS ainda cobrando)", ec2_stopped),
            ("Lambda — Ociosas ou Superdimensionadas", lambda_risks),
            ("RDS — Instâncias Paradas", rds_risks),
            ("DynamoDB — Provisionado sem uso", dynamo_risks),
            ("Load Balancers sem Targets", lb_risks),
            ("Buckets S3 Sem Lifecycle", s3_cycle),
        ]

        for title, data in sections:
            with st.expander(f"**{title}** — {len(data)} alerta(s)", expanded=bool(data)):
                if data:
                    df = pd.DataFrame(data)
                    df['Economia Mensal Estimada'] = df['Economia Mensal Estimada'].apply(
                        lambda x: f"US$ {x:.2f}"
                    )
                    st.dataframe(df.drop(columns=['Serviço'], errors='ignore'), use_container_width=True)
                else:
                    st.success("Nenhum desperdício encontrado nesta categoria.")

    # ---- TAB SEGURANÇA ----
    with tab_sec:
        st.header("Vulnerabilidades e Exposição (ISO 27001)")

        sec_sections = [
            ("Gestão de Chaves IAM (>90d)", iam_keys, "A.9 Controle de Acesso"),
            ("Bancos de Dados Públicos (RDS)", rds_pub, "A.13 Segurança de Rede"),
            ("Criptografia Faltante EBS", ebs_enc_risks, "A.10 Criptografia"),
            ("Logs e CloudTrail Desativado", ct_risks, "A.12 Segurança de Op."),
            ("S3 — Acesso Público", s3_risks, "A.9 Controle de Acesso"),
            ("Security Groups — Portas Abertas", sg_risks, "A.13 Segurança de Rede"),
            ("S3 — Sem Criptografia SSE", s3_enc_risks, "A.10 Criptografia"),
            ("IAM — Usuários sem MFA", iam_mfa_risks, "A.9 Controle de Acesso"),
        ]

        for title, data, iso_ref in sec_sections:
            with st.expander(f"**{title}** ({iso_ref}) — {len(data)} alerta(s)", expanded=bool(data)):
                if data:
                    st.dataframe(pd.DataFrame(data), use_container_width=True)
                else:
                    st.success("Nenhuma vulnerabilidade encontrada nesta categoria.")

    # ---- TAB RESUMO EXECUTIVO ----
    with tab_exec:
        st.header("📊 Resumo Executivo")

        col_a, col_b = st.columns([1, 2])

        with col_a:
            st.success(f"### 🎯 US$ {economia_total_usd:.2f}\n**Economia Mensal Projetada**")
            st.caption(
                "Baseado em: volumes EBS ociosos, EIPs não associados, "
                "EC2 paradas, Lambda superdimensionada, RDS parada, "
                "DynamoDB provisionado sem uso e Load Balancers sem tráfego."
            )

            # Breakdown por serviço
            if finops_data:
                df_breakdown = pd.DataFrame(finops_data)
                df_grouped = (
                    df_breakdown.groupby('Serviço')['Economia Mensal Estimada']
                    .sum()
                    .reset_index()
                    .sort_values('Economia Mensal Estimada', ascending=False)
                )
                df_grouped['Economia Mensal Estimada'] = df_grouped['Economia Mensal Estimada'].apply(
                    lambda x: f"US$ {x:.2f}"
                )
                st.subheader("Breakdown por Serviço")
                st.dataframe(df_grouped, use_container_width=True, hide_index=True)

        with col_b:
            st.info(
                "### 🛡️ Postura de Segurança (CSPM)\n"
                "Alinhado às diretrizes da **ISO 27001**, este ambiente foi auditado para mitigar vetores críticos:\n\n"
                "- **A.9 (Controle de Acesso):** Buckets S3 abertos e usuários IAM sem MFA.\n"
                "- **A.10 (Criptografia):** Buckets S3 sem SSE habilitado.\n"
                "- **A.13 (Segurança de Rede):** Portas administrativas (SSH/RDP) expostas para `0.0.0.0/0`.\n\n"
                "A correção destes apontamentos reduz drasticamente o risco de violações e *ransomware*."
            )

            # Distribuição de severidade
            if sec_data:
                df_sec = pd.DataFrame(sec_data)
                if 'Severidade' in df_sec.columns:
                    sev_count = df_sec['Severidade'].value_counts().reset_index()
                    sev_count.columns = ['Severidade', 'Qtd']
                    st.subheader("Alertas por Severidade")
                    st.dataframe(sev_count, use_container_width=True, hide_index=True)

    # --- BARRA LATERAL: GOVERNANÇA E HISTÓRICO ---
    st.sidebar.header("📊 Governança & Histórico")
    
    if st.sidebar.button("💾 Persistir Auditoria no Banco"):
        with st.spinner("Registrando scan no PostgreSQL..."):
            if save_audit_to_db(account_id, finops_data, sec_data, economia_total_usd):
                st.sidebar.success("Histórico salvo com sucesso! 👍")
                st.balloons()

    # Exibição do Histórico Recente na Lateral
    db = SessionLocal()
    historico = db.query(Scan).order_by(Scan.timestamp.desc()).limit(5).all()
    if historico:
        st.sidebar.divider()
        st.sidebar.write("📌 Scans Anteriores:")
        for h in historico:
            st.sidebar.caption(f"📅 {h.timestamp.strftime('%d/%m %H:%M')} | 🏆 Score: {h.score}")
    db.close()


except Exception as e:
    st.error(f"Erro de conexão com a AWS/Banco! Detalhes: {str(e)}")
