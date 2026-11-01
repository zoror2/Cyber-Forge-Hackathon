#!/bin/bash
# Runs ON the EC2 host (SSM Run Command, as root):
#   setup.sh <region> <s3://bucket/key of the code bundle> <version>
# Builds the images on the host from the bundle, prepares certs and the RDS
# runtime role, and (re)starts the stack. Idempotent.
set -euo pipefail
REGION="$1"; BUNDLE="$2"; VERSION="$3"
umask 077
mkdir -p /opt/configbridge && cd /opt/configbridge

# code: fresh copy of the bundle (no GitHub credentials on the host)
rm -rf src && mkdir src
aws s3 cp --region "$REGION" --only-show-errors "$BUNDLE" bundle.tar.gz
tar -xzf bundle.tar.gz -C src && rm bundle.tar.gz
cp src/deploy/aws/docker-compose.prod.yml src/deploy/aws/nginx-opensearch.conf src/deploy/aws/nginx-origin.conf .

# settings: SSM Parameter Store (SecureString), never in the bundle
{
  aws ssm get-parameter --region "$REGION" --name /configbridge/prod/env --with-decryption --query Parameter.Value --output text
  printf 'CB_DB_MASTER_PASSWORD=%s\n' "$(aws ssm get-parameter --region "$REGION" --name /configbridge/prod/db-master-password --with-decryption --query Parameter.Value --output text)"
  printf 'CB_API_IMAGE=configbridge-api:%s\nCB_BOOTSTRAP_IMAGE=configbridge-bootstrap:%s\n' "$VERSION" "$VERSION"
} > .env
set -a; . ./.env; set +a

mkdir -p certs
# RDS CA bundle: Postgres TLS is verified (verify-full), not just encrypted
curl -fsSL -o certs/rds-ca.pem "https://truststore.pki.rds.amazonaws.com/${REGION}/${REGION}-bundle.pem"
# OpenSearch sidecar TLS (private CA, SAN 127.0.0.1), once; CA key discarded
if [ ! -f certs/ca.pem ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=configbridge-opensearch-ca" -keyout certs/ca-key.pem -out certs/ca.pem
  openssl req -newkey rsa:3072 -nodes -subj "/CN=127.0.0.1" -keyout certs/opensearch-key.pem -out certs/os.csr
  printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > certs/ext.cnf
  openssl x509 -req -in certs/os.csr -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial -days 825 -extfile certs/ext.cnf -out certs/opensearch.pem
  rm -f certs/os.csr certs/ext.cnf certs/ca-key.pem
fi
# tunnel origin TLS (loopback only; the Cloudflare dashboard requires an https origin), once
if [ ! -f certs/origin.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout certs/origin-key.pem -out certs/origin.pem
fi
printf '%s:%s\n' "$CB_OPENSEARCH_USERNAME" "$(openssl passwd -apr1 "$CB_OPENSEARCH_PASSWORD")" > certs/htpasswd
chmod 755 certs; chmod 644 certs/ca.pem certs/opensearch.pem certs/origin.pem certs/htpasswd certs/rds-ca.pem; chmod 600 certs/opensearch-key.pem certs/origin-key.pem

# RDS runtime role: no superuser, cannot bypass row-level security (once)
export PGSSLMODE=verify-full PGSSLROOTCERT=/opt/configbridge/certs/rds-ca.pem PGPASSWORD="$CB_DB_MASTER_PASSWORD"
psql -h "$CB_DB_HOST" -U configbridge -d configbridge -v ON_ERROR_STOP=1 -v pw="$CB_APP_DB_PASSWORD" <<'SQL'
SELECT 'CREATE ROLE configbridge_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD ' || quote_literal(:'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'configbridge_app') \gexec
SQL
unset PGPASSWORD

# images built here from the bundle
docker build -q -t "configbridge-api:$VERSION" --build-arg CMD=api src
docker build -q -t "configbridge-bootstrap:$VERSION" --build-arg CMD=bootstrap src
docker compose -f docker-compose.prod.yml up -d --remove-orphans
docker compose -f docker-compose.prod.yml ps
