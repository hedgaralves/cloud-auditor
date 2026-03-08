# 🛡️ Cloud Auditor CSPM & FinOps

Um motor de auditoria leve, containerizado e focado em gerar valor imediato através da identificação de riscos de Segurança da Informação (baseado na ISO 27001) e oportunidades de redução de custos em ambientes AWS.

![Cloud Auditor Dashboard](https://img.shields.io/badge/Status-V1.0_Release-success)
![Docker Pulls](https://img.shields.io/docker/pulls/hedgaraws/cloud-auditor-web)

## 🎯 O Problema que Resolve
Ambientes de nuvem crescem rápido e, sem governança contínua, acumulam recursos ociosos (desperdício financeiro) e configurações incorretas de permissão (riscos de vazamento de dados). Esta ferramenta atua como um scanner *plug-and-play* com um painel executivo (Streamlit) para gestores de TI e arquitetos Cloud obterem um diagnóstico em tempo real.

## 🚀 Funcionalidades (v1.0)

**💰 Otimização de Custos (FinOps):**
* **Auditoria de Discos Órfãos:** Identifica volumes EBS desanexados (`available`).
* **Elastic IPs Ociosos:** Localiza EIPs alocados na conta, mas não associados a nenhuma instância.
* **Cálculo de Economia:** Projeta o valor em dólares (US$) que será economizado mensalmente com a limpeza dos recursos.

**🔒 Segurança e Conformidade (ISO 27001):**
* **Controle de Acesso (A.9):** Analisa configurações de `Public Access Block` em buckets S3, identificando exposição pública de dados.
* **Proteção de Rede (A.13):** Varre Security Groups em busca de regras excessivamente permissivas (ex: SSH/Porta 22 ou RDP/Porta 3389 abertas para `0.0.0.0/0`).

## 🏗️ Arquitetura e Tecnologias
O projeto foi construído para ser 100% agnóstico e efêmero (*Stateless*). Nenhuma credencial é armazenada no código.
* **Core:** Python 3.11 + Boto3 (AWS SDK).
* **Interface:** Streamlit + Pandas.
* **Empacotamento:** Docker (Imagem base `slim`).

## ⚙️ Como Executar (Ambiente Produtivo)

Você não precisa baixar o código para usar. Basta rodar a imagem oficial do Docker Hub injetando chaves temporárias (com permissão `ViewOnlyAccess`) da sua conta AWS:

```bash
docker run -d -p 8501:8501 \
  -e AWS_ACCESS_KEY_ID="SUA_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="SEU_SECRET_KEY" \
  -e AWS_DEFAULT_REGION="us-east-1" \
  hedgaraws/cloud-auditor-web:latest
Acesse o painel em: http://localhost:8501

🧪 Como Executar Localmente (com LocalStack)
Para testar a ferramenta sem custo na AWS, você pode usar o LocalStack. Inicie o LocalStack localmente e passe a variável AWS_ENDPOINT_URL no contêiner:

Bash
docker run -d -p 8501:8501 \
  -e AWS_ACCESS_KEY_ID="test" \
  -e AWS_SECRET_ACCESS_KEY="test" \
  -e AWS_DEFAULT_REGION="us-east-1" \
  -e AWS_ENDPOINT_URL="[http://host.docker.internal:4566](http://host.docker.internal:4566)" \
  hedgaraws/cloud-auditor-web:latest
👨‍💻 Autor
Hedgar Alves

Arquiteto Cloud & Engenheiro DevOps

LinkedIn: linkedin.com/in/hedgaralves/

GitHub: github.com/hedgaralves