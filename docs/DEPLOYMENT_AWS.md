# Production deployment: AWS + Cloudflare

This is the deployed setup for `https://cyberforge.mohithkumar.dev`: what exists,
why, how to redeploy it, and how to tear it down. **No secret values are in this
file or the repo.** They live in AWS SSM Parameter Store and Cloudflare secrets.

## Architecture

```text
browser ──https──> Cloudflare Pages (project "cyberforge")
                     ├─ /ui/*     static console (internal/ui/static)
                     └─ /*        Pages Function proxy  ── adds X-CB-Proxy-Secret,
                                                           X-CB-Client-IP, X-CB-Forwarded-Host
                                   │
                                   ▼ https
                     cyberforge-api.mohithkumar.dev (Cloudflare Tunnel "cyberforge")
                                   │  outbound-only connection from the host
AWS ap-south-1, VPC 10.20.0.0/16   ▼
  private app subnet:  EC2 t3.small (no public IP, no inbound rules, SSM only)
                         docker compose: cloudflared → api:8080
                                         api ⇄ opensearch-tls (nginx, TLS+basic auth, 127.0.0.1:9443)
                                               ⇄ opensearch (127.0.0.1:9200, loopback only)
  private DB subnets:  RDS PostgreSQL 16 (db.t4g.micro), TLS verify-full, SG allows 5432 from the app SG only
  egress:              NAT Gateway (vendor APIs, Gemini, Secrets Manager); S3 gateway endpoint
  secrets:             vendor credentials in Secrets Manager (configbridge/<tenant>/...), per-tenant KMS key
```

- The API rejects any request without the proxy secret (`403 direct_access_disabled`),
  so calling the tunnel hostname directly gets you nothing. Only `/health` answers.
  The secret is compared in constant time. The client IP and host are trusted
  only after the secret matches (`internal/api/api.go`, `fromProxy`).
- Nothing on the host listens publicly. Admin access is through SSM Session Manager.
- The runtime DB role `configbridge_app` is `NOSUPERUSER NOBYPASSRLS`. The RDS
  master is used only for migrations and the one-time data restore.

## Resource inventory (ap-south-1)

| Resource | ID / name | Notes |
|---|---|---|
| VPC | `vpc-073a13fd0c0e1df9c` (10.20.0.0/16) | flow logs → CloudWatch `/configbridge/vpc-flow` (30 days) |
| Public subnets | `subnet-0b5a2ab1c22bdcf38`, `subnet-0fcdd5a091898cebb` | NAT only |
| App subnets (private) | `subnet-0ee8f164a8541733a` (a), `subnet-0337451966b5b64ac` (b) | route 0/0 → NAT via `rtb-0c4b71e7905212aaf` |
| DB subnets (private) | `subnet-09534d7c17b84e1b8`, `subnet-0d1c686154ccc6d26`, `subnet-0f2a359e13a45d8de` (c) | subnet group `configbridge-db` |
| NAT Gateway | `nat-06bc9fcd5e399a0ab` | the main cost (~$1/day plus data) |
| App security group | `sg-029621b805111cdf5` | no ingress |
| DB security group | `sg-00490b5d3f1863cc7` | 5432 from the app SG only, no egress |
| EC2 | `i-026767bb6c8ac98a7` (t3.small, 10.20.10.227) | instance profile `configbridge-ec2`; docker, compose, psql 16, 1 GB swap |
| RDS | `configbridge` (`configbridge.c3cwoy8gsop9.ap-south-1.rds.amazonaws.com`) | PG 16, db.t4g.micro, deletion protection ON, 1-day backups (free-plan cap) |
| KMS | `alias/configbridge-secrets` | per-tenant `kms_key_id` for Secrets Manager; rotation ON |
| S3 | `configbridge-deploy-481912007303-aps1` | private, encrypted: `bundles/` (code tarballs), `migration/` (pg_dump) |
| SSM params | `/configbridge/prod/env`, `/configbridge/prod/db-master-password` | SecureString; the whole `.env` for the host |
| IAM role | `configbridge-ec2` | SSM core, ECR read; inline: Secrets Manager on `configbridge/*`, KMS via Secrets Manager only, `ssm:GetParameter` on `/configbridge/prod/*`, `s3:GetObject` on the bucket |
| IAM role | `configbridge-flowlogs` | VPC flow logs writer |
| ECR | `configbridge-api`, `configbridge-bootstrap` | **unused** (images are built on the host): delete |

Cloudflare:

| Resource | Name | Notes |
|---|---|---|
| Pages project | `cyberforge` (`cyberforge-86l.pages.dev`) | custom domain `cyberforge.mohithkumar.dev`; secret `PROXY_SECRET`; var `BACKEND_ORIGIN` |
| Tunnel | `cyberforge` | public hostname `cyberforge-api.mohithkumar.dev` → `http://api:8080`; token stored as `CB_TUNNEL_TOKEN` in SSM |

## Files

| File | Runs where | Does |
|---|---|---|
| `deploy/aws/put-env.ps1` | your PC | Builds the production `.env` (21 settings) and stores it in SSM. Generated secrets (JWT, operator token, app DB password, proxy secret, OpenSearch password) are created once and **kept on reruns**. AI key, model, limits, SIEM tenants and tunnel token are copied from your local `.env`. Never prints values. |
| `deploy/aws/setup.sh` | EC2 (root, via SSM) | Pulls the code bundle from S3, writes `.env` from SSM, fetches the RDS CA, creates OpenSearch TLS certs and htpasswd (once), creates `configbridge_app` (once), runs `docker build` on the host, then `docker compose up`. Idempotent. |
| `deploy/aws/docker-compose.prod.yml` | EC2 | bootstrap (migrations), api, opensearch, opensearch-tls, cloudflared. Every value is required (`:?`); there are no defaults. Read-only filesystems, dropped capabilities, no published ports. |
| `deploy/aws/nginx-opensearch.conf` | EC2 | TLS and basic auth in front of OpenSearch on loopback |
| `deploy/aws/restore.sh` | EC2 (once) | Loads data only from a local `pg_dump -Fc` into RDS in one transaction. It refuses if tenants already exist. |
| `deploy/pages/deploy.ps1` | your PC | Builds `deploy/pages/dist` from `internal/ui/static` and runs `wrangler pages deploy`. |
| `deploy/pages/functions/[[path]].js` | Cloudflare | The proxy. It returns `503 proxy_not_configured` if `BACKEND_ORIGIN` or `PROXY_SECRET` is missing, and does not follow redirects. |

## Redeploy new code

Prerequisites: an AWS CLI profile with access to this account, `wrangler login`,
and the repo at the commit to ship.

```powershell
# 1. bundle the code (tracked files only: no .env, no runtime data) and upload it
$v = git rev-parse --short HEAD
git archive --format=tar.gz -o "$env:TEMP\configbridge-$v.tar.gz" HEAD
aws s3 cp "$env:TEMP\configbridge-$v.tar.gz" "s3://configbridge-deploy-481912007303-aps1/bundles/configbridge-$v.tar.gz"

# 2. (only if settings changed) refresh SSM; generated secrets are kept
powershell -File deploy\aws\put-env.ps1 -EnvFile ..\..\..\.env -DbHost configbridge.c3cwoy8gsop9.ap-south-1.rds.amazonaws.com
```

3. On the host (SSM Run Command `AWS-RunShellScript` on `i-026767bb6c8ac98a7`,
   or `aws ssm start-session` and then `sudo -i`):

```bash
B=s3://configbridge-deploy-481912007303-aps1/bundles/configbridge-<v>.tar.gz
mkdir -p /opt/configbridge/boot && cd /opt/configbridge/boot
aws s3 cp --region ap-south-1 "$B" b.tgz && tar -xzf b.tgz deploy/aws/setup.sh && rm b.tgz
bash deploy/aws/setup.sh ap-south-1 "$B" <v>
```

4. Frontend: `powershell -File deploy\pages\deploy.ps1`.

Logs: `cd /opt/configbridge && docker compose -f docker-compose.prod.yml logs --tail 100 api cloudflared`.

## One-time steps already done

1. **Settings:** `put-env.ps1` was run, so SSM `/configbridge/prod/env` holds 21 settings.
2. **Data migration:** the local Docker Postgres was dumped and uploaded to
   `s3://…/migration/configbridge.dump`. It holds 6 tenants and 8 IAM users.
   `restore.sh ap-south-1 s3://…/migration/configbridge.dump <kms key arn>` loads it.
   The script assigns the KMS key to every tenant and deletes the dev `tenant-a`
   API key.
   **Stored vendor credentials are not migrated.** They were encrypted with the
   local dev keyring. Re-enter each vendor key in the console; it now goes to
   Secrets Manager.
3. **Pages proxy:** the `PROXY_SECRET` value equals `CB_PROXY_SECRET` in SSM, and
   `BACKEND_ORIGIN=https://cyberforge-api.mohithkumar.dev`. If you rotate the
   secret, update both sides, then restart the api and redeploy Pages.
4. **DNS:** `cyberforge.mohithkumar.dev` is a Pages custom domain.
   `cyberforge-api.mohithkumar.dev` is the tunnel's public hostname. Cloudflare
   creates both records.

## Account constraints found

- The AWS account is on the **free plan**. Only free-tier instance types can be
  launched (t3.large and m7i were rejected or refused), and RDS backup retention
  is capped at 1 day.
- The RDS instance was placed in ap-south-1c, which is why a third DB subnet exists.
- The wrangler OAuth token cannot create tunnels or DNS records. The tunnel was
  created in the Zero Trust dashboard.

## Security notes (fix before real customers)

- The deploy IAM user (`FEDGRID-DEPLOY`) has `AdministratorAccess`. Replace it
  with a scoped deploy role.
- There is one EC2 host and a single-AZ RDS, so there is no high availability.
  Backups are kept for 1 day.
- The OpenSearch security plugin is off. Isolation comes from loopback binding
  plus the nginx TLS and password sidecar.
- Flow logs record ALL traffic. Switch to REJECT-only to cut cost.
- Cloudflare WAF and rate-limit rules on the Pages domain are not configured. The
  API has its own per-IP limiter on login and costly routes.

## Teardown (in this order)

1. Cloudflare: delete the tunnel `cyberforge` and its DNS record, remove the Pages
   custom domain, delete the Pages project.
2. EC2: terminate `i-026767bb6c8ac98a7`.
3. RDS: turn off deletion protection, then delete `configbridge` (take a final
   snapshot if the data matters).
4. NAT Gateway `nat-06bc9fcd5e399a0ab`, then release its Elastic IP. **This stops
   most of the cost.**
5. VPC endpoint, subnets, route tables, internet gateway, security groups,
   subnet group, then the VPC. Delete the flow-log group.
6. Secrets Manager `configbridge/*` secrets, SSM `/configbridge/prod/*`, the S3
   bucket (empty it first), ECR repos, IAM roles `configbridge-ec2` and
   `configbridge-flowlogs`, and the instance profile.
7. Schedule deletion of the KMS key (7-day minimum wait).
