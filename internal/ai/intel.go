package ai

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"configbridge/internal/insights"
)

// Vendor-intel agents. Gemini searches the web; nothing it says is shown
// unless the backend fetched the cited page itself and found the quoted
// sentence on it, naming the companies involved. Unverified claims are
// dropped, never shown as "maybe".

// Claim is one verified, cited fact.
type Claim struct {
	Company string `json:"company"`
	Date    string `json:"date,omitempty"`
	Title   string `json:"title,omitempty"`
	URL     string `json:"url"`
	Quote   string `json:"quote"`
}

var claimLine = regexp.MustCompile(`(?im)^\s*[-*]?\s*(OWNS|INCIDENT)\s*:\s*(.+?)\s*$`)

func (c *Client) groundedText(ctx context.Context, prompt string, used *meter) (string, error) {
	body := map[string]any{
		"contents":         []map[string]any{{"role": "user", "parts": []map[string]any{{"text": prompt}}}},
		"tools":            []map[string]any{{"google_search": map[string]any{}}},
		"generationConfig": map[string]any{"thinkingConfig": map[string]any{"thinkingLevel": "low"}},
	}
	var text string
	e := c.retry(ctx, func() (time.Duration, error) {
		t, u, wait, e := c.geminiGrounded(ctx, body, nil)
		used.add(u)
		text = t
		return wait, e
	})
	return text, e
}

// verifyClaims fetches each cited page (public-only reader) and keeps the
// claims whose quote is on the page and passes check.
func (c *Client) verifyClaims(ctx context.Context, claims []Claim, check func(Claim) bool) []Claim {
	fetch := c.FetchDocumentation
	if fetch == nil {
		fetch = readPublicDocumentation
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := make([]bool, len(claims))
	for i, cl := range claims {
		if !publicDocURL(cl.URL) || len(compact(cl.Quote)) < 20 || !check(cl) {
			continue
		}
		wg.Add(1)
		go func(i int, cl Claim) {
			defer wg.Done()
			text, e := fetch(ctx, cl.URL)
			if e == nil && strings.Contains(strings.ToLower(compact(text)), strings.ToLower(compact(cl.Quote))) {
				mu.Lock()
				ok[i] = true
				mu.Unlock()
			}
		}(i, cl)
	}
	wg.Wait()
	out := []Claim{}
	for i, cl := range claims {
		if ok[i] {
			out = append(out, cl)
		}
	}
	return out
}

func parseClaims(text, label string) []Claim {
	var out []Claim
	for _, m := range claimLine.FindAllStringSubmatch(text, -1) {
		if !strings.EqualFold(m[1], label) {
			continue
		}
		p := strings.Split(m[2], "|")
		if len(p) < 4 {
			continue
		}
		for i := range p {
			p[i] = strings.Trim(strings.TrimSpace(p[i]), "`\"'<>*")
		}
		quote := strings.TrimSpace(strings.Join(p[3:], "|"))
		out = append(out, Claim{Company: p[0], Date: p[1], URL: p[2], Quote: quote})
		if len(out) == 10 {
			break
		}
	}
	return out
}

func mentions(text, name string) bool {
	t := strings.ToLower(text)
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if strings.Contains(t, n) {
		return true
	}
	first := strings.Fields(n)[0] // "Cisco Systems" -> "cisco"
	return len(first) >= 4 && strings.Contains(t, first)
}

var ownsWords = regexp.MustCompile(`(?i)acqui|subsidiar|bought|purchas|completed .*deal|owned by|merg`)

// Acquisitions: companies the vendor owns that the structured source missed.
func (c *Client) Acquisitions(ctx context.Context, vendor string, known []string) ([]Claim, insights.Usage, error) {
	if !c.gemini {
		return nil, insights.Usage{}, ErrSearchRequired
	}
	var used meter
	skip := ""
	if len(known) > 0 {
		skip = "\nAlready known (do not repeat): " + strings.Join(known, ", ")
	}
	text, e := c.groundedText(ctx, "Vendor: "+strings.TrimSpace(vendor)+skip+`
Search the web for companies this vendor CURRENTLY owns because it acquired them (software, hardware or security product companies), up to 10.
For each, cite one page (the vendor's press release, the acquired company's site, or a major news outlet) that states the acquisition, and copy one exact sentence from that page that names both companies and says acquired/acquisition.
Answer with lines exactly like this and nothing else:
OWNS: <company> | <year completed> | <URL> | <exact sentence copied from that page>
Never invent a company, URL or sentence. If you find none, answer: OWNS: none`, &used)
	if e != nil {
		return nil, used.total(), e
	}
	claims := c.verifyClaims(ctx, parseClaims(text, "OWNS"), func(cl Claim) bool {
		return mentions(cl.Quote, vendor) && mentions(cl.Quote, cl.Company) && ownsWords.MatchString(cl.Quote)
	})
	return claims, used.total(), nil
}

var attackWords = regexp.MustCompile(`(?i)attack|breach|exploit|compromis|ransomware|hack|intrusion|vulnerabilit|zero-day|0-day|threat actor|malicious`)

// Incidents: publicly reported attacks on one company's products or systems.
func (c *Client) Incidents(ctx context.Context, company string) ([]Claim, insights.Usage, error) {
	if !c.gemini {
		return nil, insights.Usage{}, ErrSearchRequired
	}
	var used meter
	text, e := c.groundedText(ctx, "Company: "+strings.TrimSpace(company)+`
Search the web for publicly reported cyberattacks, breaches or actively exploited vulnerabilities affecting this company's products or systems in the last five years, up to 6, most recent first.
For each, cite one page (a security advisory, CISA, the company, or a major security news outlet) and copy one exact sentence from it that names the company and describes the attack or exploitation.
Answer with lines exactly like this and nothing else:
INCIDENT: <short title> | <YYYY-MM> | <URL> | <exact sentence copied from that page>
Never invent an incident, URL or sentence. If you find none, answer: INCIDENT: none`, &used)
	if e != nil {
		return nil, used.total(), e
	}
	parsed := parseClaims(text, "INCIDENT")
	for i := range parsed { // INCIDENT lines carry the title where OWNS carries the company
		parsed[i].Title, parsed[i].Company = parsed[i].Company, company
	}
	claims := c.verifyClaims(ctx, parsed, func(cl Claim) bool {
		return mentions(cl.Quote, company) && attackWords.MatchString(cl.Quote)
	})
	return claims, used.total(), nil
}
