package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"time"
)

// Only records produced by the reviewed CISA feed contract establish catalog
// membership. A vendor's exploit flag or company name is not KEV evidence.
const kevCatalogSQL = `WITH catalog AS (
 SELECT DISTINCT e.external_id AS cve, e.fetched_at
 FROM ocsf_records e
 JOIN runs r ON r.tenant_id=e.tenant_id AND r.id=e.run_id
 JOIN configs c ON c.tenant_id=r.tenant_id AND c.id=r.connector AND c.version=r.config_version
 WHERE e.tenant_id=$1 AND e.class_uid=2002
 AND e.external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
 AND c.body#>>'{request,url}' IN ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json')
 AND c.body#>>'{auth,type}'='none' AND c.body->>'items_path'='vulnerabilities'
 AND c.body#>>'{destination,class}'='vulnerability_finding'
 AND c.body#>>'{destination,mapping,finding_info.uid,path}'='cveID'
 AND c.body#>>'{destination,mapping,vulnerabilities.0.cve.uid,path}'='cveID'
 AND COALESCE(c.body#>>'{destination,mapping,finding_info.uid,transform}','') IN ('','trim','string')
 AND COALESCE(c.body#>>'{destination,mapping,vulnerabilities.0.cve.uid,transform}','') IN ('','trim','string')
 AND e.payload#>>'{vulnerabilities,0,cve,uid}'=e.external_id
), matches AS (
 SELECT DISTINCT e.source, e.external_id, v.value#>>'{cve,uid}' AS cve, e.run_id, e.fetched_at
 FROM ocsf_records e
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.payload->'vulnerabilities')='array' THEN e.payload->'vulnerabilities' ELSE '[]'::jsonb END) v(value)
 JOIN catalog k ON k.cve=v.value#>>'{cve,uid}'
 JOIN runs r ON r.tenant_id=e.tenant_id AND r.id=e.run_id
 JOIN configs c ON c.tenant_id=r.tenant_id AND c.id=r.connector AND c.version=r.config_version
 WHERE e.tenant_id=$1 AND e.class_uid=2002 AND ($2='' OR e.source=$2)
 AND c.body#>>'{request,url}' NOT IN ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json')
) `

type KEVMatch struct {
	Connector string    `json:"connector"`
	RecordID  string    `json:"record_id"`
	CVE       string    `json:"cve"`
	RunID     string    `json:"run_id"`
	FetchedAt time.Time `json:"fetched_at"`
}
type KEVMatches struct {
	Status           string     `json:"status"`
	CatalogEntries   int64      `json:"catalog_entries"`
	CatalogFetchedAt *time.Time `json:"catalog_fetched_at"`
	Total            int64      `json:"total"`
	Matches          []KEVMatch `json:"matches"`
	Assessment       string     `json:"assessment"`
}

func (s Scope) KEVMatches(ctx context.Context, connector string, limit, offset int) (out KEVMatches, err error) {
	out.Matches = []KEVMatch{}
	out.Assessment = "Exact CVE matches in retained customer findings. Review source freshness, asset versions and remediation status; this is not proof of an active compromise."
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, kevCatalogSQL+`SELECT (SELECT count(DISTINCT cve) FROM catalog),(SELECT max(fetched_at) FROM catalog),(SELECT count(*) FROM matches)`, s.Tenant, connector).Scan(&out.CatalogEntries, &out.CatalogFetchedAt, &out.Total); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, kevCatalogSQL+`SELECT source,external_id,cve,run_id,fetched_at FROM matches ORDER BY source,external_id,cve LIMIT $3 OFFSET $4`, s.Tenant, connector, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m KEVMatch
			if e = rows.Scan(&m.Connector, &m.RecordID, &m.CVE, &m.RunID, &m.FetchedAt); e != nil {
				return e
			}
			out.Matches = append(out.Matches, m)
		}
		return rows.Err()
	})
	out.Status = "no_matches"
	if out.CatalogEntries == 0 {
		out.Status = "catalog_missing"
	} else if out.Total > 0 {
		out.Status = "matches_found"
	}
	return
}
