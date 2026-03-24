# 🛡️ Cloud Auditor CSPM & FinOps

Um motor de auditoria leve, containerizado e focado em gerar valor imediato através da identificação de riscos de Segurança da Informação (baseado na ISO 27001) e oportunidades de redução de custos em ambientes AWS.

![Cloud Auditor Dashboard](https://img.shields.io/badge/Status-V1.1.1_Release-success)
![Docker Pulls](https://img.shields.io/docker/pulls/hedgaraws/cloud-auditor)
[![Hypercommit](https://img.shields.io/badge/Hypercommit-DB2475)](https://hypercommit.com/cloud-auditor)

## 🎯 O Problema que Resolve
Ambientes de nuvem crescem rápido e, sem governança contínua, acumulam recursos ociosos (desperdício financeiro) e configurações incorretas de permissão (riscos de vazamento de dados). Esta ferramenta atua como um scanner *plug-and-play* com um painel executivo (Streamlit) para gestores de TI e arquitetos Cloud obterem um diagnóstico em tempo real.

## 🆕 Novidades na Versão 1.1.1
* **Novo UI/UX Profissional:** Reformulação completa com estética Glassmorphic (Dark Mode e Gradiente Laranja/Roxo).
* **Histórico de Auditorias:** Aba lateral para Persistir e salvar históricos recentes no banco de dados (SQLite/PostgreSQL).
* **9 Novas Varreduras Adicionadas (CSPM e FinOps):**
  * **(Sec)** Rastreio de IAM Access Keys caducas (>90 dias), mapeamento de Bancos de Dados RDS expostos (Públicos), Ausência de `CloudTrail` ligado na conta e detecção falhas de criptografia nativa no EBS.
  * **(FinOps)** Monitoramento de NAT Gateways provisionados/faturando, Snapshots de discos órfãos com mais de 90 dias, alertas de modernização com base em IA para instâncias ultrapassadas (t2/m4) e detecção de buckets do S3 sem política de ciclo de vida atrelada ao Glacier.

## 🚀 Funcionalidades (Core v1.1.1)

**💰 Otimização de Custos Extreme (FinOps):**
* **Snapshots Órfãos (>90d):** Caça rastros de Backups EBS sem utilidade retidos por longo período.
* **Modernização de EC2/RDS:** Recomenda Upgrade de famílias obsoletas (`t2, m4`) para gerações modernas (Graviton).
* **NAT Gateways Ociosos & EIPs:** Detecta NATs faturando por hora desnecessariamente e Elastic IPs órfãos.
* **S3 Lifecycle Rules:** Audita ausência de retenção automática (via Glacier) em buckets S3 maduros.
* **Discos e Instâncias Paradas:** Encontra EBS vazios (`available`), EC2s desligadas mantendo EBS em cobrança e Instâncias RDS abandonadas.
* **DynamoDB e ELB:** Localiza Load Balancers sem saídas e tabelas DynamoDB provisionadas vazias.

**🔒 Segurança e Postura CSPM (ISO 27001):**
* **Gestão de Chaves IAM (A.9.2):** Varre Access Keys ativas não rotacionadas há mais de 90 dias.
* **Vazamentos em Banco de Dados (A.13):** Detecta bancos RDS com a frágil flag de rede `PubliclyAccessible=true`.
* **Rastreabilidade e Logs (A.12):** Notifica preventivamente se as trilhas de registro do AWS **CloudTrail** forem comprometidas.
* **Criptografia em Repouso (A.10):** Encontra Volumes EBS que nasceram sem proteção nativa AES-256 no AWS KMS.
* **S3 Public Access (A.9):** Descobre buckets desprotegidos sem Bloqueio Perimetral e sem Criptografia SSE.
* **Security Groups e MFA (A.13, A.9.4):** Denuncia portas de gerenciamento 22/3389 expostas e Usuários Master sem duplo-fator Auth.

## 🏗️ Arquitetura e Tecnologias
O projeto possui backend persistente estruturado no padrão MVC leve, com arquitetura otimizada para segurança máxima:
* **Core:** Python 3.11 + Boto3 (AWS SDK).
* **Interface (UI/UX):** Streamlit (Dark-Theme) + Pandas.
* **Persistência (Banco de Dados):** SQLAlchemy ORM via `models.py` (Geração de Histórico contínuo em SQLite ou PostgreSQL).
* **Serviços AWS Auditados:** S3, EC2 (Generations), EBS (Snapshots e Volumes), RDS, IAM (Keys e MFA), DynamoDB, NAT Gateways, Elastic IPs, Load Balancers, CloudTrail.
* **Empacotamento Seguro:** Imagem Docker Hardened (`Alpine 3.21`) com mitigação agressiva de vulnerabilidades de SO (Zero CVEs).

## ⚙️ Como Executar (Ambiente Produtivo)

Escolha uma das duas opções abaixo dependendo da sua arquitetura e preferência.

---

### Opção A — Imagem pronta do Docker Hub (sem build, amd64)

Nenhum download de código necessário. A imagem pública funciona diretamente em máquinas **Intel/AMD64**.

> **Importante:** a imagem do Docker Hub usa PostgreSQL como banco padrão. Passe `DATABASE_URL` apontando para `/tmp` e monte um volume nesse mesmo caminho para persistência:

```bash
docker run -d -p 8501:8501 -v cloud-auditor-data:/tmp -e DATABASE_URL="sqlite:////tmp/cloudauditor.db" -e AWS_ACCESS_KEY_ID="SUA_ACCESS_KEY" -e AWS_SECRET_ACCESS_KEY="SEU_SECRET_KEY" -e AWS_DEFAULT_REGION="us-east-1" hedgaraws/cloud-auditor:1.1.1
```

Verifique se o volume foi montado corretamente:

```bash
docker inspect $(docker ps -q --filter ancestor=hedgaraws/cloud-auditor:1.1.1) --format '{{json .Mounts}}'
```

A saída deve conter `"Name":"cloud-auditor-data"` e `"Destination":"/tmp"`. Se o resultado for `[]`, o container foi iniciado sem o volume — pare, remova e reinicie com o comando acima:

```bash
docker stop $(docker ps -q --filter ancestor=hedgaraws/cloud-auditor:1.1.1) && docker rm $(docker ps -aq --filter ancestor=hedgaraws/cloud-auditor:1.1.1)
```

> Em Mac Apple Silicon (M1/M2/M3/M4) esta imagem roda via emulação e pode exibir um aviso de plataforma. Use a Opção B para build nativo.

---

### Opção B — Build local (recomendado para ARM64 / Apple Silicon)

**Passo 1 — Clone o repositório e entre na pasta:**

```bash
git clone https://github.com/hedgaralves/cloud-auditor.git
cd cloud-auditor
```

**Passo 2 — Build da imagem para sua arquitetura:**

```bash
# Apple Silicon (M1/M2/M3/M4)
docker build --platform linux/arm64 -t cloud-auditor:local .

# Intel / AMD64
docker build --platform linux/amd64 -t cloud-auditor:local .
```

**Passo 3 — Execute:**

```bash
docker run -d -p 8501:8501 -v cloud-auditor-data:/app/data -e AWS_ACCESS_KEY_ID="SUA_ACCESS_KEY" -e AWS_SECRET_ACCESS_KEY="SEU_SECRET_KEY" -e AWS_DEFAULT_REGION="us-east-1" cloud-auditor:local
```

---

Acesse o painel em: **http://localhost:8501**

### 🔐 Permissões IAM Necessárias (AWS Policy)
Para que o Cloud Auditor V2 consiga rodar as 14 varreduras sem erros de `AccessDenied`, crie uma Policy no IAM (com escopo estrito de Leitura) e associe ao usuário que provê as credenciais:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudAuditorV2ReadOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVolumes",
                "ec2:DescribeAddresses",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSnapshots",
                "ec2:DescribeNatGateways",
                "lambda:ListFunctions",
                "rds:DescribeDBInstances",
                "dynamodb:ListTables",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTargetHealth",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetEncryptionConfiguration",
                "s3:GetLifecycleConfiguration",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "cloudtrail:DescribeTrails"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🧪 Como Executar Localmente (com LocalStack)

Para testar sem custos na AWS real, use o **LocalStack** — um emulador local dos serviços AWS.

### Pré-requisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado e em execução
- [LocalStack CLI](https://docs.localstack.cloud/getting-started/installation/) (opcional, mas recomendado)

---

### Passo 1 — Iniciar o LocalStack

```bash
# Via Docker (funciona em amd64 e arm64)
docker run -d \
  --name localstack \
  -p 4566:4566 \
  -e SERVICES=s3,ec2,iam,rds,dynamodb,elbv2,lambda,cloudtrail \
  localstack/localstack:latest
```

Aguarde até o LocalStack estar saudável:

```bash
docker logs -f localstack
# Procure pela linha: "Ready."
```

---

### Passo 2 — Semear recursos vulneráveis (mock)

Clone o repositório e execute o script de seed para popular o LocalStack com recursos simulados:

```bash
git clone https://github.com/hedgaralves/cloud-auditor.git
cd cloud-auditor

pip install boto3
AWS_ENDPOINT_URL=http://localhost:4566 python mock_aws_env.py
```

---

### Passo 3 — Build da imagem para sua arquitetura

O build local garante compatibilidade nativa sem avisos de plataforma.

**Apple Silicon / ARM64 (M1, M2, M3, M4):**

```bash
docker build --platform linux/arm64 -t cloud-auditor:local .
```

**Intel / AMD64:**

```bash
docker build --platform linux/amd64 -t cloud-auditor:local .
```

---

### Passo 4 — Executar o Cloud Auditor apontando para o LocalStack

```bash
docker run -d -p 8501:8501 \
  -v cloud-auditor-data:/app/data \
  -e AWS_ACCESS_KEY_ID="test" \
  -e AWS_SECRET_ACCESS_KEY="test" \
  -e AWS_DEFAULT_REGION="us-east-1" \
  -e AWS_ENDPOINT_URL="http://host.docker.internal:4566" \
  cloud-auditor:local
```

Se o comando multi-linha falhar no seu terminal, use a versão em uma única linha:

```bash
docker run -d -p 8501:8501 -v cloud-auditor-data:/app/data -e AWS_ACCESS_KEY_ID="test" -e AWS_SECRET_ACCESS_KEY="test" -e AWS_DEFAULT_REGION="us-east-1" -e AWS_ENDPOINT_URL="http://host.docker.internal:4566" cloud-auditor:local
```

Acesse o painel em: **http://localhost:8501**

> **Nota:** `host.docker.internal` resolve para o host a partir de dentro do contêiner no Docker Desktop (Mac e Windows). No Linux, substitua por `172.17.0.1` ou o IP da interface `docker0`.

---

### Build Multi-Plataforma (amd64 + arm64 simultâneo)

Para gerar e publicar uma imagem que funciona em ambas as arquiteturas:

```bash
# Criar e ativar um builder multi-arch (necessário apenas uma vez)
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap

# Build e push para o Docker Hub
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t SEU_USUARIO/cloud-auditor:latest \
  --push \
  .
```

Após o push, o `docker run` usa automaticamente a camada correta para cada arquitetura — sem necessidade de flag `--platform`.

---

## 👨‍💻 Autor
Hedgar Alves
Arquiteto Cloud &  DevOps

Colaboração
Luiz Otávio Campedelli
Cloud Engineer 

LinkedIn: linkedin.com/in/hedgaralves/

GitHub: github.com/hedgaralves
