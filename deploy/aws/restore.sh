#!/bin/bash
# Runs ON the EC2 host once, after setup.sh has migrated the empty RDS schema:
#   restore.sh <region> <s3 uri of a pg_dump -Fc file> <tenant KMS key ARN>
# Loads DATA ONLY into the already-migrated schema, in one transaction.
# Not migrated: stored vendor credentials (encrypted with the local dev keyring,
# meaningless to the AWS Secrets Manager backend: re-enter them) and the
# schema_migrations rows (production migrations already wrote them).
set -euo pipefail
REGION="$1"; DUMP="$2"; KMS="$3"
cd /opt/configbridge
set -a; . ./.env; set +a
export PGSSLMODE=verify-full PGSSLROOTCERT=/opt/configbridge/certs/rds-ca.pem PGPASSWORD="$CB_DB_MASTER_PASSWORD"
PSQL=(psql -h "$CB_DB_HOST" -U configbridge -d configbridge -v ON_ERROR_STOP=1 -At)
if [ "$("${PSQL[@]}" -c 'select count(*) from tenants')" != "0" ]; then echo "target already has tenants: refusing to restore twice" >&2; exit 1; fi
aws s3 cp --region "$REGION" --only-show-errors "$DUMP" data.dump
pg_restore -l data.dump | grep -Ev 'TABLE DATA public (credentials_values|credentials_meta|schema_migrations) ' > restore.list
pg_restore -h "$CB_DB_HOST" -U configbridge -d configbridge --data-only --no-owner --no-acl --single-transaction --exit-on-error -L restore.list data.dump
"${PSQL[@]}" -v kms="$KMS" <<'SQL'
UPDATE tenants SET kms_key_id = :'kms' WHERE kms_key_id = '';
DELETE FROM api_keys WHERE tenant_id = 'tenant-a';
SQL
rm -f data.dump restore.list
"${PSQL[@]}" -c "select 'tenants', count(*) from tenants union all select 'iam_users', count(*) from iam_users union all select 'configs', count(*) from configs union all select 'ocsf_records', count(*) from ocsf_records union all select 'runs', count(*) from runs"
