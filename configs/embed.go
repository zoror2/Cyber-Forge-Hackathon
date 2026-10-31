// Package configs embeds the shipped live connector configs so the AI drafter
// can show the model real, validated examples (no duplicated copies).
package configs

import _ "embed"

//go:embed github_members.json
var GitHubMembers []byte

//go:embed nvd_kev_cves.json
var NVDKEVCVEs []byte
