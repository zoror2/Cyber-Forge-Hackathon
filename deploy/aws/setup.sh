#!/bin/bash
# Runs ON the EC2 instance (via SSM Run Command), from /opt/configbridge.
#   setup.sh <ssm-env-parameter> <region>
# Idempotent: certs/passwords are created once; images are pulled; stack is (re)started.
set -euo pipefail
PARAM="$1"; REGION="$2"
cd /opt/configbridge
umask 077
aws ssm get-parameter --region "$REGION" --name "$PARAM" --with-decryption --query Parameter.Value --output text > .env
set -a; . ./.env; set +a

# OpenSearch sidecar TLS (private CA, SAN 127.0.0.1) and basic-auth file, once.
mkdir -p certs
if [ ! -f certs/ca.pem ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=configbridge-opensearch-ca" \
    -keyout certs/ca-key.pem -out certs/ca.pem
  openssl req -newkey rsa:3072 -nodes -subj "/CN=127.0.0.1" -keyout certs/opensearch-key.pem -out certs/os.csr
  printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > certs/ext.cnf
  openssl x509 -req -in certs/os.csr -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial -days 825 \
    -extfile certs/ext.cnf -out certs/opensearch.pem
  rm -f certs/os.csr certs/ext.cnf certs/ca-key.pem   # CA key not kept: nothing else gets signed
fi
printf '%s:%s\n' "$CB_OPENSEARCH_USERNAME" "$(openssl passwd -apr1 "$CB_OPENSEARCH_PASSWORD")" > certs/htpasswd
# the api runs as non-root and needs the CA; the key stays root-only (nginx master reads it as root)
chmod 755 certs; chmod 644 certs/ca.pem certs/opensearch.pem certs/htpasswd; chmod 600 certs/opensearch-key.pem
chmod 755 initdb; chmod 755 initdb/*.sh

aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${CB_API_IMAGE%%/*}"
docker compose -f docker-compose.prod.yml pull --quiet
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
