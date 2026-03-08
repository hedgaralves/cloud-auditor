import streamlit as st
import pandas as pd
import boto3
import os
from botocore.exceptions import ClientError

# Configuração da página Web
st.set_page_config(page_title="Cloud Auditor - CSPM", page_icon="🛡️", layout="wide")
AWS_ENDPOINT = os.getenv("AWS_ENDPOINT_URL")

def get_aws_account_id():
    sts = boto3.client('sts', endpoint_url=AWS_ENDPOINT, region_name='us-east-1')
    return sts.get_caller_identity()["Account"]

# --- FUNÇÕES DE FINOPS (COM CUSTOS) ---
def audit_ebs_volumes():
    ec2 = boto3.client('ec2', endpoint_url=AWS_ENDPOINT, region_name='us-east-1')
    volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])
    resultados = []
    for v in volumes.get('Volumes', []):
        custo_mensal = v['Size'] * 0.08
        resultados.append({
            'ID do Recurso': v['VolumeId'], 
            'Detalhe': f"{v['Size']} GB ({v['VolumeType']})", 
            'Economia Mensal Estimada': custo_mensal
        })
    return resultados

def audit_elastic_ips():
    ec2 = boto3.client('ec2', endpoint_url=AWS_ENDPOINT, region_name='us-east-1')
    ips = ec2.describe_addresses()
    resultados = []
    for ip in ips.get('Addresses', []):
        if 'AssociationId' not in ip:
            resultados.append({
                'ID do Recurso': ip['PublicIp'], 
                'Detalhe': 'Elastic IP não associado', 
                'Economia Mensal Estimada': 3.60
            })
    return resultados

# --- FUNÇÕES DE SEGURANÇA ---
def audit_s3_public_access():
    s3 = boto3.client('s3', endpoint_url=AWS_ENDPOINT, region_name='us-east-1')
    buckets = s3.list_buckets()['Buckets']
    exposed_buckets = []
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            config = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
            if not (config.get('BlockPublicAcls') and config.get('BlockPublicPolicy')):
                exposed_buckets.append({'ID do Recurso': bucket_name, 'Risco': 'Exposição Pública Possível (S3)'})
        except ClientError:
            exposed_buckets.append({'ID do Recurso': bucket_name, 'Risco': 'Sem Bloqueio Configurado (S3)'})
    return exposed_buckets

def audit_security_groups():
    ec2 = boto3.client('ec2', endpoint_url=AWS_ENDPOINT, region_name='us-east-1')
    sgs = ec2.describe_security_groups()
    risky_sgs = []
    for sg in sgs.get('SecurityGroups', []):
        for rule in sg.get('IpPermissions', []):
            if rule.get('FromPort') in [22, 3389]:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        risky_sgs.append({'ID do Recurso': sg['GroupId'], 'Risco': f"Porta {rule['FromPort']} aberta para a internet (0.0.0.0/0)"})
    return risky_sgs

# --- INTERFACE STREAMLIT ---
st.title("🛡️ Cloud Auditor CSPM & FinOps")
st.markdown("Plataforma de Auditoria Contínua baseada em **ISO 27001** e redução de custos em nuvem.")

try:
    account_id = get_aws_account_id()
    st.success(f"✅ Conectado com sucesso na conta AWS: **{account_id}**")
    
    # Coleta de Dados
    ebs_risks = audit_ebs_volumes()
    eip_risks = audit_elastic_ips()
    s3_risks = audit_s3_public_access()
    sg_risks = audit_security_groups()
    
    finops_data = ebs_risks + eip_risks
    total_finops_alertas = len(finops_data)
    total_sec_alertas = len(s3_risks) + len(sg_risks)
    
    economia_total_usd = sum(item['Economia Mensal Estimada'] for item in finops_data)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("💰 Economia Potencial (Mês)", f"US$ {economia_total_usd:.2f}", delta="Redução Imediata")
    col2.metric("⚠️ Alertas de FinOps", total_finops_alertas, delta_color="inverse")
    col3.metric("🚨 Alertas de Segurança", total_sec_alertas, delta_color="inverse")
    
    st.divider()
    
    tab1, tab2 = st.tabs(["💰 Detalhamento de Custos Ociosos", "🔒 Detalhamento de Segurança"])
    
    with tab1:
        st.header("Recursos Cobrando Sem Uso")
        if finops_data:
            df_finops = pd.DataFrame(finops_data)
            df_finops['Economia Mensal Estimada'] = df_finops['Economia Mensal Estimada'].apply(lambda x: f"US$ {x:.2f}")
            st.dataframe(df_finops, use_container_width=True)
        else:
            st.info("Nenhum desperdício encontrado. Parabéns!")

    with tab2:
        st.header("Vulnerabilidades e Exposição (ISO 27001)")
        sec_data = s3_risks + sg_risks
        if sec_data:
            st.dataframe(pd.DataFrame(sec_data), use_container_width=True)
        else:
            st.info("Nenhuma vulnerabilidade crítica encontrada.")

    # --- NOVO DASHBOARD INFERIOR (RESUMO EXECUTIVO) ---
    st.divider()
    st.header("📊 Resumo Executivo")
    
    bot_col1, bot_col2 = st.columns([1, 2]) # A coluna de segurança fica mais larga para caber o texto
    
    with bot_col1:
        st.success(f"### 🎯 US$ {economia_total_usd:.2f} \n**Economia Mensal Projetada**")
        st.caption("Cálculo baseado na exclusão de volumes EBS disponíveis e liberação de EIPs ociosos.")
        
    with bot_col2:
        st.info("### 🛡️ Postura de Segurança (CSPM)\n"
                "Alinhado às diretrizes da **ISO 27001**, este ambiente foi auditado para mitigar vetores críticos de ataque:\n"
                "- **A.9 (Controle de Acesso):** Bloqueio proativo contra vazamento de dados via buckets S3 abertos.\n"
                "- **A.13 (Segurança de Rede):** Fechamento de portas administrativas (ex: 22 SSH) indevidamente expostas para a internet (`0.0.0.0/0`).\n"
                "A correção destes apontamentos reduz drasticamente o risco de violações e *ransomware*.")

except Exception as e:
    st.error(f"Erro de conexão com a AWS/LocalStack! Detalhes: {str(e)}")