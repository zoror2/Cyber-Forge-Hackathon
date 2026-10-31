package store

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
)

type ExposedCredential struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
}
type Exposure struct {
	Vendor            string              `json:"vendor"`
	Connector         string              `json:"connector"`
	KEVCount          int                 `json:"kev_count"`
	NewestDateAdded   string              `json:"newest_date_added"`
	CVEIDs            []string            `json:"cve_ids"`
	Products          []string            `json:"products"`
	EvidenceFetchedAt time.Time           `json:"evidence_fetched_at"`
	Credentials       []ExposedCredential `json:"credentials"`
	Assessment        string              `json:"assessment"`
}

// Exposure uses each tenant's existing KEV copy. It never loads secret values or
// calls a model. Source checks use the config revision that produced the record,
// so changing a config after a run cannot relabel an arbitrary feed as CISA.
func (s Scope) Exposure(ctx context.Context, connector string, limit, offset int) (out []Exposure, err error) {
	out = []Exposure{}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `WITH matches AS (
   SELECT c.id,c.body->>'vendor' AS vendor,c.body#>>'{auth,secret}' AS secret,
    e.external_id AS cve,to_char(cb_ts(e.payload->'time') AT TIME ZONE 'UTC','YYYY-MM-DD') AS added,
    btrim(e.payload#>>'{unmapped,product}') AS product,e.fetched_at
   FROM configs c
   JOIN vendor_aliases a ON lower(btrim(c.body->>'vendor'))=lower(a.vendor)
   JOIN ocsf_records e ON e.tenant_id=c.tenant_id AND e.class_uid=2002
    AND lower(btrim(e.payload#>>'{vulnerabilities,0,vendor_name}'))=a.kev_vendor AND lower(btrim(e.payload#>>'{unmapped,product}'))=a.kev_product
   JOIN runs r ON r.tenant_id=e.tenant_id AND r.id=e.run_id
   JOIN configs src ON src.tenant_id=r.tenant_id AND src.id=r.connector AND src.version=r.config_version
   WHERE c.tenant_id=$1 AND c.status='live' AND ($2='' OR c.id=$2)
    AND e.external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
    AND src.body#>>'{request,url}'='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    AND src.body#>>'{auth,type}'='none' AND src.body->>'items_path'='vulnerabilities'
    AND src.body#>>'{destination,class}'='vulnerability_finding'
    AND src.body->'destination'->'mapping'->'finding_info.uid'->>'path'='cveID'
    AND src.body->'destination'->'mapping'->'vulnerabilities.0.vendor_name'->>'path'='vendorProject'
    AND src.body->'destination'->'mapping'->'unmapped.product'->>'path'='product'
    AND src.body->'destination'->'mapping'->'time'->>'path'='dateAdded'
  ) SELECT m.id,m.vendor,count(DISTINCT m.cve),max(m.added),
   (array_agg(DISTINCT m.cve ORDER BY m.cve))[1:20],(array_agg(DISTINCT m.product ORDER BY m.product))[1:20],max(m.fetched_at),
   COALESCE((SELECT jsonb_agg(jsonb_build_object('id',k.credential_id,'name',k.name,'owner',k.owner)) FROM credentials_meta k WHERE k.tenant_id=$1 AND k.name=m.secret),'[]'::jsonb)
   FROM matches m GROUP BY m.id,m.vendor,m.secret ORDER BY m.id LIMIT $3 OFFSET $4`, s.Tenant, connector, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var x Exposure
			var creds []byte
			if e = rows.Scan(&x.Connector, &x.Vendor, &x.KEVCount, &x.NewestDateAdded, &x.CVEIDs, &x.Products, &x.EvidenceFetchedAt, &creds); e != nil {
				return e
			}
			if e = json.Unmarshal(creds, &x.Credentials); e != nil {
				return e
			}
			x.Assessment = "vendor_match_requires_deployment_review"
			out = append(out, x)
		}
		return rows.Err()
	})
	return
}
