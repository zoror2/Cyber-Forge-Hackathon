package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"configbridge/pkg/jsonvalue"

	"gopkg.in/yaml.v3"
)

// OpenAPI evidence: a vendor's official OpenAPI/Swagger file is
// machine-readable truth about its API. The model only picks one operation
// from the spec's own catalog and writes a config; verifySpec then checks every
// execution setting structurally against that operation. Nothing the spec does
// not declare (path, parameter, auth scheme, response field) can pass.

const maxSpecBytes = 16 << 20

type apiSpec struct {
	url, version string
	servers      []string
	schemes      map[string]any   // security schemes by name
	security     []map[string]any // global requirements
	secDeclared  bool
	root         map[string]any
	ops          map[string]*specOp // "GET /path"
}

type specOp struct {
	key, path, summary, desc string
	tags                     []string
	params                   []specParam
	security                 []map[string]any
	secDeclared              bool
	response                 map[string]any // 2xx JSON body schema
	headers                  []string       // 2xx response headers, lower case
}

type specParam struct {
	name, in, typ, desc string
	required            bool
	enum                []string
}

type specRef struct {
	doc *apiSpec
	op  *specOp
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }
func str(v any) string         { s, _ := v.(string); return s }

// normalize turns YAML's non-string-keyed maps (e.g. unquoted 200) into JSON shape.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalize(x)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = normalize(x)
		}
		return m
	case []any:
		for i := range t {
			t[i] = normalize(t[i])
		}
		return t
	}
	return v
}

var errNotSpec = fmt.Errorf("%w: not an OpenAPI 3 or Swagger 2 document", ErrDocumentation)

// parseSpec reads a JSON or YAML spec as published; no format is forced.
func parseSpec(source, text string) (*apiSpec, error) {
	var raw any
	t := strings.TrimSpace(text)
	var e error
	if strings.HasPrefix(t, "{") {
		e = json.Unmarshal([]byte(t), &raw)
	} else {
		e = yaml.Unmarshal([]byte(t), &raw)
	}
	root := obj(normalize(raw))
	if e != nil || root == nil {
		return nil, errNotSpec
	}
	return buildSpec(source, root)
}

func isSpec(root map[string]any) bool {
	v3, v2 := strings.HasPrefix(fmt.Sprint(root["openapi"]), "3."), strings.HasPrefix(fmt.Sprint(root["swagger"]), "2.")
	return (v2 || v3) && len(obj(root["paths"])) > 0
}

var scriptBody = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)

// embeddedSpecs: docs portals often ship the OpenAPI document inside the page
// (ReadMe's ssr-props JSON, Redoc's __redoc_state, JSON script blocks). That
// is the vendor's own spec, read as data; nothing on the page is executed.
func embeddedSpecs(source, page string) []*apiSpec {
	var out []*apiSpec
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 12 || len(out) >= 5 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if isSpec(t) {
				if sp, e := buildSpec(source, t); e == nil {
					out = append(out, sp)
				}
				return
			}
			for _, x := range t {
				walk(x, depth+1)
			}
		case []any:
			for _, x := range t {
				walk(x, depth+1)
			}
		}
	}
	for _, m := range scriptBody.FindAllStringSubmatch(page, -1) {
		body := m[1]
		if !strings.Contains(body, `"paths"`) {
			continue
		}
		// a JSON block, or a JS assignment whose value is JSON
		for start, tries := strings.IndexAny(body, "{["), 0; start >= 0 && tries < 20; tries++ {
			var v any
			if json.NewDecoder(strings.NewReader(body[start:])).Decode(&v) == nil {
				walk(v, 0)
				break
			}
			next := strings.Index(body[start+1:], "={")
			if next < 0 {
				break
			}
			start += next + 2
		}
	}
	return out
}

func buildSpec(source string, root map[string]any) (*apiSpec, error) {
	if !isSpec(root) {
		return nil, errNotSpec
	}
	v3 := strings.HasPrefix(fmt.Sprint(root["openapi"]), "3.")
	paths := obj(root["paths"])
	s := &apiSpec{url: source, root: root, ops: map[string]*specOp{}}
	if v3 {
		s.version = "OpenAPI " + fmt.Sprint(root["openapi"])
		for _, sv := range arr(root["servers"]) {
			if u := str(obj(sv)["url"]); u != "" {
				s.servers = append(s.servers, serverVariants(u, obj(obj(sv)["variables"]))...)
			}
		}
		s.schemes = obj(obj(root["components"])["securitySchemes"])
	} else {
		s.version = "Swagger 2.0"
		if host := str(root["host"]); host != "" {
			s.servers = []string{"https://" + host + str(root["basePath"])}
		} else if base := str(root["basePath"]); base != "" {
			s.servers = []string{base}
		}
		s.schemes = obj(root["securityDefinitions"])
	}
	if len(s.servers) == 0 { // per both specs: relative to where the spec is served
		s.servers = []string{"/"}
	}
	if sec, ok := root["security"]; ok {
		s.security, s.secDeclared = requirements(sec), true
	}
	for p, item := range paths {
		it := s.resolve(obj(item))
		get := s.resolve(obj(it["get"]))
		if get == nil {
			continue
		}
		op := &specOp{key: "GET " + p, path: p, summary: strings.TrimSpace(str(get["summary"])), desc: strings.TrimSpace(str(get["description"]))}
		for _, t := range arr(get["tags"]) {
			op.tags = append(op.tags, str(t))
		}
		byName := map[string]int{}
		for _, list := range []any{it["parameters"], get["parameters"]} {
			for _, x := range arr(list) {
				pm := s.resolve(obj(x))
				if pm == nil {
					continue
				}
				sc := s.resolve(obj(pm["schema"]))
				sp := specParam{name: str(pm["name"]), in: str(pm["in"]), typ: str(pm["type"]), desc: str(pm["description"]), required: pm["required"] == true}
				if sp.typ == "" {
					sp.typ = str(sc["type"])
				}
				enum := arr(pm["enum"])
				if enum == nil {
					enum = arr(sc["enum"])
				}
				for _, v := range enum {
					sp.enum = append(sp.enum, fmt.Sprint(v))
				}
				if i, ok := byName[sp.in+" "+sp.name]; ok { // operation overrides path item
					op.params[i] = sp
					continue
				}
				byName[sp.in+" "+sp.name] = len(op.params)
				op.params = append(op.params, sp)
			}
		}
		if sec, ok := get["security"]; ok {
			op.security, op.secDeclared = requirements(sec), true
		} else {
			op.security, op.secDeclared = s.security, s.secDeclared
		}
		responses := obj(get["responses"])
		for _, code := range []string{"200", "2XX", "2xx", "201", "203", "206", "default"} {
			r := s.resolve(obj(responses[code]))
			if r == nil {
				continue
			}
			if v3 {
				content := obj(r["content"])
				types := make([]string, 0, len(content))
				for k := range content {
					types = append(types, k)
				}
				sort.Strings(types)
				for _, k := range types {
					if strings.Contains(k, "json") {
						op.response = s.resolve(obj(obj(content[k])["schema"]))
						break
					}
				}
			} else {
				op.response = s.resolve(obj(r["schema"]))
			}
			for h := range obj(r["headers"]) {
				op.headers = append(op.headers, strings.ToLower(h))
			}
			if op.response != nil {
				break
			}
		}
		s.ops[op.key] = op
	}
	return s, nil
}

// serverVariants: the server as written, with its path variables set to the
// spec's defaults (host stays customer-specific), and fully defaulted.
func serverVariants(u string, vars map[string]any) []string {
	out := []string{u}
	if len(vars) == 0 {
		return out
	}
	fill := func(s string) string {
		for name, v := range vars {
			if def, ok := obj(v)["default"]; ok {
				s = strings.ReplaceAll(s, "{"+name+"}", fmt.Sprint(def))
			}
		}
		return s
	}
	if i := strings.Index(u, "://"); i >= 0 {
		host, path, _ := strings.Cut(u[i+3:], "/")
		if mixed := u[:i+3] + host + "/" + fill(path); path != "" && mixed != u {
			out = append(out, strings.TrimSuffix(mixed, "/"))
		}
	}
	if full := fill(u); !contains(out, full) {
		out = append(out, full)
	}
	return out
}

func requirements(v any) []map[string]any {
	out := []map[string]any{}
	for _, x := range arr(v) {
		out = append(out, obj(x))
	}
	return out
}

// resolve follows local $refs; external or cyclic refs resolve to nothing.
func (s *apiSpec) resolve(m map[string]any) map[string]any {
	for i := 0; m != nil && i < 20; i++ {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil
		}
		var cur any = s.root
		for _, p := range strings.Split(ref[2:], "/") {
			p, _ = url.PathUnescape(p)
			cur = obj(cur)[strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")]
		}
		m = obj(cur)
	}
	return nil
}

func (s *apiSpec) branches(sc map[string]any) []map[string]any {
	var out []map[string]any
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		for _, b := range arr(sc[k]) {
			if r := s.resolve(obj(b)); r != nil {
				out = append(out, r)
			}
		}
	}
	return out
}

// props: declared properties, including those of allOf/oneOf/anyOf branches.
func (s *apiSpec) props(sc map[string]any, depth int) map[string]any {
	out := map[string]any{}
	sc = s.resolve(sc)
	if sc == nil || depth > 8 {
		return out
	}
	for k, v := range obj(sc["properties"]) {
		out[k] = v
	}
	for _, b := range s.branches(sc) {
		for k, v := range s.props(b, depth+1) {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}

// arrayItems: the record schema when sc is an array.
func (s *apiSpec) arrayItems(sc map[string]any, depth int) (map[string]any, bool) {
	sc = s.resolve(sc)
	if sc == nil || depth > 8 {
		return nil, false
	}
	if items, ok := sc["items"]; ok || sc["type"] == "array" {
		r := s.resolve(obj(items))
		if r == nil {
			r = map[string]any{}
		}
		return r, true
	}
	for _, b := range s.branches(sc) {
		if items, ok := s.arrayItems(b, depth+1); ok {
			return items, true
		}
	}
	return nil, false
}

// schemaAt follows a dotted or JSON-pointer response path through the
// schema; numeric segments step into arrays. Undeclared keys (including
// free-form additionalProperties) are not proof.
func (s *apiSpec) schemaAt(sc map[string]any, path string) (map[string]any, bool) {
	parts, ok := jsonvalue.Tokens(path)
	if !ok {
		return nil, false
	}
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		if strings.Trim(part, "0123456789") == "" {
			if items, ok := s.arrayItems(sc, 0); ok {
				sc = items
				continue
			}
		}
		next, ok := s.props(sc, 0)[part]
		if !ok {
			return nil, false
		}
		sc = s.resolve(obj(next))
		if sc == nil {
			sc = map[string]any{}
		}
	}
	return sc, true
}

func (s *apiSpec) typeOf(sc map[string]any) string {
	sc = s.resolve(sc)
	if t := str(sc["type"]); t != "" {
		if f := str(sc["format"]); f != "" {
			return t + " (" + f + ")"
		}
		return t
	}
	for _, b := range s.branches(sc) {
		if t := s.typeOf(b); t != "any" {
			return t
		}
	}
	return "any"
}

// collections: the items_path of each record array in a response (depth <= 2).
func (s *apiSpec) collections(resp map[string]any) []string {
	if resp == nil {
		return nil
	}
	if _, ok := s.arrayItems(resp, 0); ok {
		return []string{""}
	}
	out := []string{}
	top := s.props(resp, 0)
	for _, k := range sortedKeys(top) {
		if _, ok := s.arrayItems(obj(top[k]), 0); ok {
			out = append(out, k)
			continue
		}
		inner := s.props(obj(top[k]), 0)
		for _, k2 := range sortedKeys(inner) {
			if _, ok := s.arrayItems(obj(inner[k2]), 0); ok {
				out = append(out, k+"."+k2)
			}
		}
	}
	return out
}

// flatten lists a record's field paths as mapping paths (nested arrays as .0.).
func (s *apiSpec) flatten(sc map[string]any, prefix string, depth int, out *[]string) {
	sc = s.resolve(sc)
	if sc == nil || depth > 6 || len(*out) >= 250 {
		return
	}
	if items, ok := s.arrayItems(sc, 0); ok && prefix != "" {
		s.flatten(items, prefix+".0", depth+1, out)
		return
	}
	p := s.props(sc, 0)
	if len(p) == 0 {
		if prefix != "" {
			*out = append(*out, prefix+": "+s.typeOf(sc))
		}
		return
	}
	for _, k := range sortedKeys(p) {
		next := k
		if prefix != "" {
			next = prefix + "." + k
		}
		s.flatten(obj(p[k]), next, depth+1, out)
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// listOps: GET operations whose response holds a record array.
func (s *apiSpec) listOps() []*specOp {
	out := []*specOp{}
	for _, op := range s.ops {
		if len(s.collections(op.response)) > 0 {
			out = append(out, op)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func (s *apiSpec) catalog() (string, map[string]*specOp) {
	var b strings.Builder
	listed := map[string]*specOp{}
	for _, op := range s.listOps() {
		if len(listed) == 1200 { // Datadog alone has 420 list operations
			break
		}
		listed[op.key] = op
		fmt.Fprintf(&b, "%s | %s", op.key, trunc(strings.Join(strings.Fields(op.summary), " "), 120))
		if len(op.tags) > 0 {
			fmt.Fprintf(&b, " | %s", strings.Join(op.tags, ", "))
		}
		b.WriteString("\n")
	}
	return b.String(), listed
}

// allowedSchemes: names of schemes one of which satisfies the operation;
// noAuth when the spec says the operation needs none.
func (s *apiSpec) allowedSchemes(op *specOp) (names []string, noAuth bool) {
	if !op.secDeclared {
		if len(s.schemes) == 0 {
			return nil, true
		}
		return sortedKeys(s.schemes), false
	}
	if len(op.security) == 0 {
		return nil, true
	}
	seen := map[string]bool{}
	for _, req := range op.security {
		if len(req) == 0 {
			noAuth = true
		}
		if len(req) == 1 { // AND-combined schemes are not supported
			for k := range req {
				if !seen[k] {
					seen[k] = true
					names = append(names, k)
				}
			}
		}
	}
	sort.Strings(names)
	return names, noAuth
}

func (s *apiSpec) tokenURLs(sc map[string]any) []string {
	var out []string
	if u := str(sc["tokenUrl"]); u != "" && str(sc["flow"]) == "application" { // Swagger 2
		out = append(out, u)
	}
	if u := str(obj(obj(sc["flows"])["clientCredentials"])["tokenUrl"]); u != "" {
		out = append(out, u)
	}
	for i, u := range out {
		if base, e := url.Parse(s.url); e == nil {
			if r, e := base.Parse(u); e == nil {
				out[i] = r.String()
			}
		}
	}
	return out
}

func (s *apiSpec) describeScheme(name string) string {
	sc := s.resolve(obj(s.schemes[name]))
	d := name + ": " + str(sc["type"])
	switch str(sc["type"]) {
	case "apiKey":
		d += fmt.Sprintf(" in %s %q", str(sc["in"]), str(sc["name"]))
	case "http":
		d += " " + str(sc["scheme"])
	case "oauth2":
		if t := s.tokenURLs(sc); len(t) > 0 {
			d += " client_credentials tokenUrl " + strings.Join(t, ", ")
		} else {
			d += " (no client-credentials flow; a token obtained elsewhere is sent as Bearer)"
		}
	}
	if desc := compact(str(sc["description"])); desc != "" {
		d += " — " + trunc(desc, 300)
	}
	return d
}

// excerpt: everything the model may use, for exactly one operation.
func (s *apiSpec) excerpt(op *specOp) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OPENAPI SPEC %s (%s)\nSERVERS: %s\nOPERATION: %s\nSUMMARY: %s\n", s.url, s.version, strings.Join(s.servers, " , "), op.key, op.summary)
	if op.desc != "" {
		fmt.Fprintf(&b, "DESCRIPTION: %s\n", trunc(compact(op.desc), 1500))
	}
	b.WriteString("PARAMETERS:\n")
	for _, p := range op.params {
		req := "optional"
		if p.required {
			req = "required"
		}
		fmt.Fprintf(&b, "- %s (%s, %s, %s)", p.name, p.in, p.typ, req)
		if len(p.enum) > 0 {
			fmt.Fprintf(&b, " one of: %s", trunc(strings.Join(p.enum, ", "), 200))
		}
		fmt.Fprintf(&b, ": %s\n", trunc(compact(p.desc), 200))
	}
	names, noAuth := s.allowedSchemes(op)
	b.WriteString("SECURITY (any one of):\n")
	if noAuth {
		b.WriteString("- none (no authentication)\n")
	}
	for _, hs := range s.headerCombos(op) { // preferred: what customers normally have
		fmt.Fprintf(&b, "- all together, as auth static with one header each: apiKey headers %q\n", hs)
	}
	// API keys first: customers have them; OAuth apps need extra setup
	rank := func(n string) int {
		sc := s.resolve(obj(s.schemes[n]))
		switch {
		case str(sc["type"]) == "apiKey":
			return 0
		case str(sc["type"]) == "basic" || strings.EqualFold(str(sc["scheme"]), "basic"):
			return 1
		}
		return 2
	}
	sort.SliceStable(names, func(i, j int) bool { return rank(names[i]) < rank(names[j]) })
	for _, n := range names {
		b.WriteString("- " + s.describeScheme(n) + "\n")
	}
	if len(op.headers) > 0 {
		fmt.Fprintf(&b, "RESPONSE HEADERS: %s\n", strings.Join(op.headers, ", "))
	}
	top := s.props(op.response, 0)
	if len(top) > 0 {
		b.WriteString("TOP-LEVEL RESPONSE FIELDS (for cursor_path/next_url_path):\n")
		for _, k := range sortedKeys(top) {
			fmt.Fprintf(&b, "- %s: %s\n", k, s.typeOf(obj(top[k])))
		}
	}
	for _, c := range s.collections(op.response) {
		fmt.Fprintf(&b, "RECORDS at items_path %q; fields of one record as mapping paths:\n", c)
		var fields []string
		target := op.response
		if c != "" {
			target, _ = s.schemaAt(op.response, c)
		}
		items, _ := s.arrayItems(target, 0)
		s.flatten(items, "", 0, &fields)
		for _, f := range fields {
			b.WriteString("- " + f + "\n")
		}
	}
	return b.String()
}

var tmplPart = regexp.MustCompile(`\{[^}]+\}|your-[a-zA-Z0-9_-]+`)

func tmpl(s string) string { return strings.ToLower(tmplPart.ReplaceAllString(s, "{}")) }

// serverURL resolves a (possibly relative or templated) server against the spec URL.
func (s *apiSpec) serverURL(raw string) (host, base string, ok bool) {
	if strings.HasPrefix(raw, "{") && strings.Contains(raw, "://") { // templated scheme
		raw = "https" + raw[strings.Index(raw, "://"):]
	}
	safe := tmplPart.ReplaceAllStringFunc(raw, func(string) string { return "your-x" })
	u, e := url.Parse(safe)
	if e != nil {
		return "", "", false
	}
	if !u.IsAbs() {
		specURL, e := url.Parse(s.url)
		if e != nil {
			return "", "", false
		}
		u = specURL.ResolveReference(u)
		return u.Hostname(), strings.TrimSuffix(u.Path, "/"), u.Scheme == "https"
	}
	// keep the original (unsubstituted) host/path text for template matching
	rest := raw[strings.Index(raw, "://")+3:]
	hostPart, path, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(hostPart, ":"); i > 0 && !strings.Contains(hostPart[i:], "}") {
		hostPart = hostPart[:i]
	}
	return hostPart, strings.TrimSuffix("/"+path, "/"), u.Scheme == "https"
}

func (op *specOp) query(name string) (specParam, bool) {
	for _, p := range op.params {
		if p.in == "query" && p.name == name {
			return p, true
		}
	}
	return specParam{}, false
}

// verifySpec checks the config structurally against the chosen operation.
func verifySpec(r Request, cfg config.Config) ([]config.Issue, []Evidence) {
	sp, op := r.spec.doc, r.spec.op
	var issues []config.Issue
	var ev []Evidence
	problem := func(field, msg string) { issues = append(issues, config.Issue{Field: field, Message: msg}) }
	cite := func(kind, value, where string) {
		ev = append(ev, Evidence{Kind: kind, Value: value, URL: sp.url, Quote: "spec " + where})
	}
	u, e := url.Parse(cfg.Request.URL)
	if e != nil || cfg.Request.Method != "GET" {
		problem("request.url", "GET request with a valid URL required")
		return issues, nil
	}
	matched := false
	for _, raw := range sp.servers {
		host, base, https := sp.serverURL(raw)
		h, ch := tmpl(host), tmpl(u.Hostname())
		hostOK := https && (h == ch || (h == "{}" && strings.Contains(ch, "{}")))
		if hostOK && tmpl(base+op.path) == tmpl(strings.TrimSuffix(u.Path, "/")) {
			matched = true
			cite("api_host", u.Hostname(), "servers: "+raw)
			cite("endpoint", cfg.Request.URL, "paths."+op.path+".get")
			break
		}
	}
	if !matched {
		problem("request.url", "host and path must be a spec server plus "+op.path+" exactly, path parameters as your-* placeholders")
	}
	if r.Scope != "enterprise" && strings.Contains(strings.ToLower(u.Path), "/enterprises/") {
		problem("scope", "Enterprise data was not requested")
	}
	paging := map[string]bool{}
	pg := cfg.Pagination
	for _, p := range []string{pg.PageParam, pg.OffsetParam, pg.SizeParam, pg.CursorParam} {
		if p != "" {
			paging[p] = true
		}
	}
	for name, value := range cfg.Request.Params {
		p, ok := op.query(name)
		switch {
		case !ok:
			problem("request.params."+name, "not a query parameter of "+op.key+" in the spec")
		case len(p.enum) > 0 && !contains(p.enum, value):
			problem("request.params."+name, "value must be one of the spec's values: "+trunc(strings.Join(p.enum, ", "), 200))
		default:
			cite("query_param", name, "paths."+op.path+".get.parameters."+name)
		}
	}
	for _, p := range op.params {
		_, set := cfg.Request.Params[p.name]
		if p.in == "query" && p.required && !set && !paging[p.name] {
			problem("request.params."+p.name, "required by the spec")
		}
		if p.in == "path" && p.required && !strings.Contains(op.path, "{"+p.name+"}") {
			problem("request.url", "path parameter "+p.name+" undeclared in route")
		}
	}
	for name := range cfg.Request.Headers {
		declared := strings.EqualFold(name, "Accept")
		for _, p := range op.params {
			declared = declared || (p.in == "header" && strings.EqualFold(p.name, name))
		}
		if !declared {
			problem("request.headers."+name, "header is not declared by the spec")
		}
	}
	if scheme, ok := sp.authMatches(op, cfg.Auth); ok {
		cite("auth", cfg.Auth.Type, scheme)
	} else {
		names, noAuth := sp.allowedSchemes(op)
		if noAuth {
			names = append(names, "none")
		}
		problem("auth", "authentication must be one of the operation's security schemes: "+strings.Join(names, ", "))
	}
	items, ok := op.response, op.response != nil
	if ok && cfg.ItemsPath != "" {
		items, ok = sp.schemaAt(op.response, cfg.ItemsPath)
	}
	if ok {
		items, ok = sp.arrayItems(items, 0)
	}
	if !ok {
		problem("items_path", "the spec's response has no array at "+fmt.Sprintf("%q", cfg.ItemsPath))
	} else {
		cite("items_path", cfg.ItemsPath, "response schema")
	}
	declared := func(name string) bool { _, ok := op.query(name); return name == "" || ok }
	inResponse := func(path string) bool { _, ok := sp.schemaAt(op.response, path); return path != "" && ok }
	pageOK := false
	switch pg.Type {
	case "none":
		pageOK = true
	case "page":
		pageOK = pg.PageParam != "" && declared(pg.PageParam) && declared(pg.SizeParam)
	case "offset":
		pageOK = pg.OffsetParam != "" && declared(pg.OffsetParam) && declared(pg.SizeParam)
	case "cursor":
		pageOK = pg.CursorParam != "" && declared(pg.CursorParam) && declared(pg.SizeParam) && inResponse(pg.CursorPath)
	case "next_url":
		pageOK = inResponse(pg.NextURLPath)
	case "link":
		text := strings.ToLower(op.desc)
		for _, p := range op.params {
			text += " " + strings.ToLower(p.desc)
		}
		pageOK = contains(op.headers, "link") || strings.Contains(text, "link header")
	}
	if pageOK {
		cite("pagination", pg.Type, "parameters/response of "+op.key)
	} else {
		problem("pagination", "strategy and every parameter/path must be declared by the spec for "+op.key)
	}
	for dest, path := range mappedPaths(cfg, problem) {
		if !ok {
			break
		}
		if _, found := sp.schemaAt(items, path); !found {
			problem("destination.mapping."+dest, "response path "+path+" is not in the spec's record schema; do not invent it")
			continue
		}
		cite("field", path, "record schema")
	}
	return issues, ev
}

// headerCombos: requirements needing several apiKey headers at once.
func (s *apiSpec) headerCombos(op *specOp) [][]string {
	var out [][]string
	for _, req := range op.security {
		if len(req) < 2 {
			continue
		}
		var hs []string
		for n := range req {
			sc := s.resolve(obj(s.schemes[n]))
			if str(sc["type"]) != "apiKey" || str(sc["in"]) != "header" {
				hs = nil
				break
			}
			hs = append(hs, str(sc["name"]))
		}
		if len(hs) > 1 {
			sort.Strings(hs)
			out = append(out, hs)
		}
	}
	return out
}

// authMatches: the configured auth is one of the operation's schemes.
func (s *apiSpec) authMatches(op *specOp, a engine.Auth) (string, bool) {
	names, noAuth := s.allowedSchemes(op)
	if a.Type == "none" {
		return "security: none", noAuth
	}
	// several apiKey headers required together (e.g. DD-API-KEY + DD-APPLICATION-KEY)
	if a.Type == "static" {
		for _, req := range s.headerCombos(op) {
			all := true
			for _, h := range req {
				found := false
				for _, x := range a.Headers {
					found = found || (strings.EqualFold(x.Name, h) && strings.TrimSpace(secretRef.ReplaceAllString(x.Value, "")) == "")
				}
				all = all && found
			}
			if all && len(a.Headers) == len(req) {
				return "security: all of " + strings.Join(req, " + "), true
			}
		}
	}
	for _, n := range names {
		sc := s.resolve(obj(s.schemes[n]))
		t, scheme := str(sc["type"]), strings.ToLower(str(sc["scheme"]))
		ok := false
		switch {
		case t == "apiKey" && str(sc["in"]) == "header":
			h := str(sc["name"])
			ok = a.Type == "api_key" && strings.EqualFold(a.Header, h)
			if a.Type == "static" {
				// e.g. "SSWS {{secret.value}}" or "accessKey={{secret.a}};secretKey={{secret.b}}":
				// every literal part of the value must be stated by the scheme itself
				said := str(sc["description"]) // not the scheme's name: "apiToken" must not prove "Token"
				for _, x := range a.Headers {
					if !strings.EqualFold(x.Name, h) {
						continue
					}
					ok = true
					for _, lit := range secretRef.Split(x.Value, -1) {
						if lit = strings.TrimSpace(lit); lit != "" && !strings.Contains(said, lit) {
							ok = false
						}
					}
				}
			}
		case t == "http" && scheme == "bearer", t == "openIdConnect":
			ok = a.Type == "bearer"
		case (t == "http" && scheme == "basic") || t == "basic":
			ok = a.Type == "basic"
		case t == "oauth2":
			ok = a.Type == "bearer" || (a.Type == "oauth2_client_credentials" && contains(s.tokenURLs(sc), a.TokenURL))
		}
		if ok {
			return "securitySchemes." + n, true
		}
	}
	return "", false
}

var secretRef = regexp.MustCompile(`\{\{\s*secret\.[a-zA-Z0-9_]+\s*\}\}`)

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func readPublicSpec(ctx context.Context, raw string) (string, error) {
	if !publicDocURL(raw) {
		return "", ErrDocumentation
	}
	u, _ := url.Parse(raw)
	u.Fragment = ""
	b, _, e := fetchPublic(ctx, u, "application/json, application/yaml, text/yaml, text/plain", maxSpecBytes)
	return string(b), e
}
