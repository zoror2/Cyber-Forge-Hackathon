package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// KEVHit: one actively exploited CVE from the tenant's live KEV copy.
type KEVHit struct {
	CVE     string `json:"cve"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Added   string `json:"added"`
}

// KEVForCompanies returns the KEV entries per company name: the KEV vendor
// equals the name, or (names of 4+ letters) the KEV product contains it, as
// CISA often files a subsidiary's product under the parent ("Cisco" /
// "Meraki ..."). Only records collected by a live CISA KEV source count.
func (s Scope) KEVForCompanies(ctx context.Context, names []string) (map[string][]KEVHit, int, error) {
	out := map[string][]KEVHit{}
	total := 0
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	lower := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			lower = append(lower, n)
		}
	}
	err := s.WithTx(ctx, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, kevSource+` SELECT count(*) FROM kev`, s.Tenant).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, kevSource+`
  SELECT n, cve, vendor, product, added FROM kev, unnest($2::text[]) AS n
  WHERE lower(vendor)=n OR (length(n)>=4 AND strpos(lower(product), n)>0)
  ORDER BY n, added DESC`, s.Tenant, lower)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			var h KEVHit
			if e := rows.Scan(&n, &h.CVE, &h.Vendor, &h.Product, &h.Added); e != nil {
				return e
			}
			out[n] = append(out[n], h)
		}
		return rows.Err()
	})
	return out, total, err
}

// kevSource: the tenant's KEV records from a live, reviewed-shape KEV source
// (same rules as Exposure).
const kevSource = `WITH kev AS (
  SELECT DISTINCT ON (e.external_id) e.external_id AS cve,
   btrim(coalesce(e.payload#>>'{vulnerabilities,0,vendor_name}','')) AS vendor,
   btrim(coalesce(e.payload#>>'{unmapped,product}','')) AS product,
   coalesce(to_char(cb_ts(e.payload->'time') AT TIME ZONE 'UTC','YYYY-MM-DD'),'') AS added
  FROM ocsf_records e
  JOIN runs r ON r.tenant_id=e.tenant_id AND r.id=e.run_id
  JOIN configs src ON src.tenant_id=r.tenant_id AND src.id=r.connector AND src.version=r.config_version
  WHERE e.tenant_id=$1 AND e.class_uid=2002 AND e.external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
   AND src.body#>>'{request,url}' IN ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json')
   AND src.body->'destination'->'mapping'->'vulnerabilities.0.vendor_name'->>'path'='vendorProject'
   AND src.body->'destination'->'mapping'->'unmapped.product'->>'path'='product'
  ORDER BY e.external_id, e.fetched_at DESC)`
