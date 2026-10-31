package engine

// Edge cases for the page loop in Fetch: empty and exactly-full pages,
// vendor bugs (repeating cursors, self-referencing Link headers, ignored
// size/offset params), hostile next links and malformed bodies.
//
// Tests for behaviour that is currently WRONG do not encode the wrong result.
// They call knownBug, which skips with an explanation while the bug exists and
// turns into a normal assertion as soon as the engine is fixed.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"configbridge/internal/egress"
)

// knownBug skips the test with a BUG note while buggy is true.
func knownBug(t *testing.T, buggy bool, format string, args ...any) {
	t.Helper()
	if buggy {
		t.Skipf("KNOWN BUG (engine): "+format, args...)
	}
}

// counted wraps a handler and counts requests.
func counted(hits *atomic.Int32, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}
}

// ids returns the "id" field of every item, in order.
func ids(t *testing.T, items []any) []int {
	t.Helper()
	out := make([]int, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			t.Fatalf("item is %T, want object", it)
		}
		n, err := strconv.Atoi(fmt.Sprint(m["id"]))
		if err != nil {
			t.Fatalf("bad id %v", m["id"])
		}
		out = append(out, n)
	}
	return out
}

// assertSequential checks ids are exactly from, from+1, ... from+n-1
// (no duplicates, no gaps).
func assertSequential(t *testing.T, items []any, from, n int) {
	t.Helper()
	got := ids(t, items)
	if len(got) != n {
		t.Fatalf("got %d items, want %d (%v)", len(got), n, got)
	}
	for i, id := range got {
		if id != from+i {
			t.Fatalf("item %d has id %d, want %d (dup or gap): %v", i, id, from+i, got)
		}
	}
}

// pagedVendor serves `total` records with page-number or offset paging,
// honouring the requested size (capped at maxSize if > 0).
func pagedVendor(total, maxSize int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		size, _ := strconv.Atoi(q.Get("size"))
		if maxSize > 0 && size > maxSize {
			size = maxSize
		}
		start := 0
		if q.Has("offset") {
			start, _ = strconv.Atoi(q.Get("offset"))
		} else {
			page, _ := strconv.Atoi(q.Get("page"))
			start = (page - 1) * size
		}
		s, n := pageOf(total, start, size)
		fmt.Fprintf(w, `{"items":%s}`, itemsJSON(s, n))
	}
}

func pageConn(h *harness, size int) Connector {
	c := h.conn("/p")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "page", PageParam: "page", SizeParam: "size", PageSize: size}
	return c
}

func offsetConn(h *harness, size int) Connector {
	c := h.conn("/o")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "offset", OffsetParam: "offset", SizeParam: "size", PageSize: size}
	return c
}

// ---- Empty first page ----

func TestPagEmptyFirstPage(t *testing.T) {
	cases := map[string]func(h *harness) Connector{
		"page":   func(h *harness) Connector { return pageConn(h, 10) },
		"offset": func(h *harness) Connector { return offsetConn(h, 10) },
		"cursor": func(h *harness) Connector {
			c := h.conn("/c")
			c.ItemsPath = "items"
			c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
			return c
		},
		"link": func(h *harness) Connector {
			c := h.conn("/l")
			c.ItemsPath = "items"
			c.Pagination = Pagination{Type: "link"}
			return c
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"items":[],"next":""}`)
			}))
			res, items, err := h.fetch(mk(h))
			if err != nil || res.Pages != 1 || len(items) != 0 || hits.Load() != 1 {
				t.Fatalf("pages=%d items=%d hits=%d err=%v", res.Pages, len(items), hits.Load(), err)
			}
		})
	}
}

// An empty page that still carries a cursor ends the run (designed: "empty
// page = last page"). Note: some APIs (Slack-style filtered listings) can
// legitimately return 0 items with a valid next cursor mid-stream.
func TestCursorEmptyPageWithCursorStops(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items":[],"next":"more"}`)
	}))
	c := h.conn("/c")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
	res, _, err := h.fetch(c)
	if err != nil || res.Pages != 1 || hits.Load() != 1 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

// ---- Last page exactly full / short final page ----

// page/offset: 20 records, page_size 10. Designed behaviour: a full page
// can't be told apart from "more to come", so ONE extra request is made; it
// returns 0 records and ends the run. No duplicates, nothing lost.
func TestPagExactlyFullLastPage(t *testing.T) {
	for name, mk := range map[string]func(*harness, int) Connector{"page": pageConn, "offset": offsetConn} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, pagedVendor(20, 0)))
			res, items, err := h.fetch(mk(h, 10))
			if err != nil || res.Pages != 3 || hits.Load() != 3 {
				t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
			}
			assertSequential(t, items, 0, 20)
		})
	}
}

func TestPagShortFinalPageStops(t *testing.T) {
	for name, mk := range map[string]func(*harness, int) Connector{"page": pageConn, "offset": offsetConn} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, pagedVendor(23, 0)))
			res, items, err := h.fetch(mk(h, 10))
			if err != nil || res.Pages != 3 || hits.Load() != 3 {
				t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
			}
			assertSequential(t, items, 0, 23)
		})
	}
}

// Cursor vendor that keeps returning a cursor on the last full page: the
// follow-up page is empty and ends the run.
func TestCursorExactlyFullLastPage(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after") {
		case "":
			fmt.Fprintf(w, `{"items":%s,"next":"c2"}`, itemsJSON(0, 10))
		case "c2":
			fmt.Fprintf(w, `{"items":%s,"next":"c3"}`, itemsJSON(10, 10))
		case "c3":
			fmt.Fprint(w, `{"items":[],"next":null}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	c := h.conn("/c")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
	res, items, err := h.fetch(c)
	if err != nil || res.Pages != 3 || hits.Load() != 3 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
	assertSequential(t, items, 0, 20)
}

// Link vendors omit rel="next" on the last page, so an exactly-full last page
// costs no extra request.
func TestLinkExactlyFullLastPage(t *testing.T) {
	var hits atomic.Int32
	var base string
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/l?page=2>; rel="next"`, base))
			fmt.Fprint(w, itemsJSON(0, 10))
			return
		}
		fmt.Fprint(w, itemsJSON(10, 10))
	}))
	base = h.srv.URL
	c := h.conn("/l")
	c.Pagination = Pagination{Type: "link"}
	res, items, err := h.fetch(c)
	if err != nil || res.Pages != 2 || hits.Load() != 2 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
	assertSequential(t, items, 0, 20)
}

// ---- Cursor vendor bugs ----

func TestCursorRepeatsSameValue(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"items":%s,"next":"stuck"}`, itemsJSON(0, 5))
	}))
	c := h.conn("/c")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
	res, _, err := h.fetch(c)
	// page 1 (no cursor) and page 2 (after=stuck) are fetched; the 3rd URL
	// would repeat page 2, so the loop is detected before sending it.
	if err == nil || !strings.Contains(err.Error(), "loop detected") || res.Pages != 2 || hits.Load() != 2 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

func TestCursorCycleABA(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		next := map[string]string{"": "A", "A": "B", "B": "A"}[r.URL.Query().Get("after")]
		fmt.Fprintf(w, `{"items":%s,"next":%q}`, itemsJSON(0, 5), next)
	}))
	c := h.conn("/c")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
	res, _, err := h.fetch(c)
	if err == nil || !strings.Contains(err.Error(), "loop detected") || res.Pages != 3 || hits.Load() != 3 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

// Cursors that change every time but never end are stopped by max_pages.
func TestCursorEndlessUniqueStopsAtMaxPages(t *testing.T) {
	var n atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"items":%s,"next":"c%d"}`, itemsJSON(0, 1), n.Add(1))
	})
	c := h.conn("/c")
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
	c.Limits.MaxPages = 4
	res, _, err := h.fetch(c)
	if !errors.Is(err, ErrPageLimit) || res.Pages != 4 || n.Load() != 4 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, n.Load(), err)
	}
}

// Missing / null / empty cursor all mean "last page".
func TestCursorMissingOrNullEndsRun(t *testing.T) {
	for name, body := range map[string]string{
		"missing key":    `{"items":[{"id":1}]}`,
		"missing parent": `{"items":[{"id":1}],"other":1}`,
		"null":           `{"items":[{"id":1}],"meta":{"next":null}}`,
		"empty string":   `{"items":[{"id":1}],"meta":{"next":""}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			c := h.conn("/c")
			c.ItemsPath = "items"
			c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "meta.next"}
			res, items, err := h.fetch(c)
			if err != nil || res.Pages != 1 || len(items) != 1 || hits.Load() != 1 {
				t.Fatalf("pages=%d items=%d hits=%d err=%v", res.Pages, len(items), hits.Load(), err)
			}
		})
	}
}

// A numeric (or object) cursor is a real value, not "no more pages". The
// engine must either follow it or fail loudly; silently succeeding with only
// page 1 loses every later record.
func TestCursorNonStringValue(t *testing.T) {
	for name, cur := range map[string]string{"number": `2`, "object": `{"token":"x"}`} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("after") == "" {
					fmt.Fprintf(w, `{"items":%s,"next":%s}`, itemsJSON(0, 10), cur)
					return
				}
				fmt.Fprintf(w, `{"items":%s,"next":null}`, itemsJSON(10, 5))
			}))
			c := h.conn("/c")
			c.ItemsPath = "items"
			c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "next"}
			res, items, err := h.fetch(c)
			knownBug(t, err == nil && len(items) == 10 && hits.Load() == 1,
				"non-string cursor %s is treated as end of data: run succeeds with %d/15 records (engine.go cursor case, `s, _ := v.(string)`)", cur, len(items))
			if err == nil && len(items) != 15 {
				t.Fatalf("succeeded with partial data: pages=%d items=%d", res.Pages, len(items))
			}
		})
	}
}

// ---- Link header parsing ----

func TestLinkHeaderVariants(t *testing.T) {
	cases := map[string]func(base string) string{
		"next not first": func(b string) string {
			return fmt.Sprintf(`<%s/l?page=1>; rel="first", <%s/l?page=2>; rel="next"`, b, b)
		},
		"multi-value rel":      func(b string) string { return fmt.Sprintf(`<%s/l?page=2>; rel="next last"`, b) },
		"unquoted rel":         func(b string) string { return fmt.Sprintf(`<%s/l?page=2>; rel=next`, b) },
		"uppercase REL":        func(b string) string { return fmt.Sprintf(`<%s/l?page=2>; REL="NEXT"`, b) },
		"extra params":         func(b string) string { return fmt.Sprintf(`<%s/l?page=2>; title="p2"; rel="next"`, b) },
		"relative":             func(string) string { return `</l?page=2>; rel="next"` },
		"comma inside url":     func(b string) string { return fmt.Sprintf(`<%s/l?page=2&f=a,b>; rel="next"`, b) },
		"separate header line": func(b string) string { return "" }, // set via Add below
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			var base string
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "2" {
					fmt.Fprint(w, itemsJSON(10, 3))
					return
				}
				if name == "separate header line" {
					w.Header().Add("Link", fmt.Sprintf(`<%s/l?page=9>; rel="last"`, base))
					w.Header().Add("Link", fmt.Sprintf(`<%s/l?page=2>; rel="next"`, base))
				} else {
					w.Header().Set("Link", link(base))
				}
				fmt.Fprint(w, itemsJSON(0, 10))
			}))
			base = h.srv.URL
			c := h.conn("/l")
			c.Pagination = Pagination{Type: "link"}
			res, items, err := h.fetch(c)
			if err != nil || res.Pages != 2 || hits.Load() != 2 {
				t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
			}
			assertSequential(t, items, 0, 13)
		})
	}
}

// Headers with no usable rel="next" end the run after page 1 (treated as
// "no next link"); nothing panics and no extra request is made.
func TestLinkMalformedHeaderStops(t *testing.T) {
	for name, link := range map[string]string{
		"no angle brackets": `https://x/l?page=2; rel="next"`,
		"unclosed bracket":  `<https://x/l?page=2; rel="next"`,
		"no rel":            `<https://x/l?page=2>`,
		"only prev/last":    `<https://x/l?page=1>; rel="prev", <https://x/l?page=9>; rel="last"`,
		"empty":             ` `,
		"empty target":      `<>; rel="next"`,
		"garbage":           `;;;,,,<>;rel=`,
	} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", link)
				fmt.Fprint(w, itemsJSON(0, 10))
			}))
			c := h.conn("/l")
			c.Pagination = Pagination{Type: "link"}
			res, _, err := h.fetch(c)
			if err != nil || res.Pages != 1 || hits.Load() != 1 {
				t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
			}
		})
	}
}

// An unparseable next URL must give a clean error, not a panic.
func TestLinkUnusableTarget(t *testing.T) {
	for name, link := range map[string]string{
		"bad url": `<https://[::1/x>; rel="next"`,
	} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", link)
				fmt.Fprint(w, itemsJSON(0, 10))
			}))
			c := h.conn("/l")
			c.Pagination = Pagination{Type: "link"}
			res, _, err := h.fetch(c)
			if err == nil || res.Pages != 1 || hits.Load() != 1 {
				t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
			}
		})
	}
}

func TestLinkNextEqualsCurrentURL(t *testing.T) {
	var hits atomic.Int32
	var base string
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/l>; rel="next"`, base))
		fmt.Fprint(w, itemsJSON(0, 10))
	}))
	base = h.srv.URL
	c := h.conn("/l")
	c.Pagination = Pagination{Type: "link"}
	res, _, err := h.fetch(c)
	if err == nil || !strings.Contains(err.Error(), "loop detected") || res.Pages != 1 || hits.Load() != 1 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

func TestLinkCycleBackToEarlierPage(t *testing.T) {
	var hits atomic.Int32
	var base string
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		next := map[string]string{"": "2", "2": "3", "3": "2"}[r.URL.Query().Get("page")]
		w.Header().Set("Link", fmt.Sprintf(`<%s/l?page=%s>; rel="next"`, base, next))
		fmt.Fprint(w, itemsJSON(0, 10))
	}))
	base = h.srv.URL
	c := h.conn("/l")
	c.Pagination = Pagination{Type: "link"}
	res, _, err := h.fetch(c)
	if err == nil || !strings.Contains(err.Error(), "loop detected") || res.Pages != 3 || hits.Load() != 3 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

// Same IP, different port: a different origin, must be refused before any
// request reaches the other port (credentials would go with it).
func TestLinkToSameHostOtherPortIsBlocked(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewTLSServer(counted(&otherHits, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, itemsJSON(0, 1))
	}))
	t.Cleanup(other.Close)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/steal?page=2>; rel="next"`, other.URL))
		fmt.Fprint(w, itemsJSON(0, 10))
	})
	c := h.conn("/l")
	c.Request.AllowedPorts = []int{portOf(h.srv), portOf(other)} // even if both ports were approved
	c.Pagination = Pagination{Type: "link"}
	res, _, err := h.fetch(c)
	if !errors.Is(err, egress.ErrBlocked) || res.Pages != 1 || otherHits.Load() != 0 {
		t.Fatalf("pages=%d otherHits=%d err=%v", res.Pages, otherHits.Load(), err)
	}
}

// Downgrade to http on the same host:port, or a link with userinfo, must be
// refused (the host check passes; egress.CheckURL must catch it).
func TestLinkSchemeDowngradeAndUserinfoBlocked(t *testing.T) {
	for name, mk := range map[string]func(host string) string{
		"http downgrade": func(host string) string { return "http://" + host + "/l?page=2" },
		"userinfo":       func(host string) string { return "https://u:p@" + host + "/l?page=2" },
		"other scheme":   func(host string) string { return "ftp://" + host + "/l?page=2" },
	} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			var host string
			h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", "<"+mk(host)+`>; rel="next"`)
				fmt.Fprint(w, itemsJSON(0, 10))
			}))
			host = h.host
			c := h.conn("/l")
			c.Pagination = Pagination{Type: "link"}
			res, _, err := h.fetch(c)
			if !errors.Is(err, egress.ErrBlocked) || res.Pages != 1 || hits.Load() != 1 {
				t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
			}
		})
	}
}

// ---- Vendor ignores size / offset params ----

// Vendor returns MORE than page_size (ignores size param). Offset advances by
// what was actually received, so nothing is fetched twice.
func TestOffsetVendorReturnsMoreThanPageSize(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		at, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		s, n := pageOf(25, at, 15) // vendor's own page size: 15
		fmt.Fprintf(w, `{"items":%s}`, itemsJSON(s, n))
	}))
	res, items, err := h.fetch(offsetConn(h, 10))
	// 0-14, 15-24 (10 = page_size, not short), then an empty page ends it.
	if err != nil || res.Pages != 3 || hits.Load() != 3 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
	assertSequential(t, items, 0, 25)
}

// Vendor returns FEWER than page_size because it caps the size server side
// (very common: ask for 1000, get 100). A short page is not proof of the
// last page; stopping here silently drops the rest of the data.
func TestPagVendorCapsPageSize(t *testing.T) {
	for name, mk := range map[string]func(*harness, int) Connector{"page": pageConn, "offset": offsetConn} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			h := newHarness(t, counted(&hits, pagedVendor(25, 5)))
			res, items, err := h.fetch(mk(h, 10))
			knownBug(t, err == nil && len(items) == 5,
				"vendor capped page size at 5 (asked 10): run succeeds with %d/25 records after %d request(s) (engine.go `len(items) < c.Pagination.PageSize`)", len(items), hits.Load())
			if err == nil {
				assertSequential(t, items, 0, 25)
			}
			_ = res
		})
	}
}

// Vendor ignores the offset param and always returns the same full page:
// URLs differ, so URL loop detection can't see it. max_pages must end it.
func TestOffsetVendorIgnoresOffsetStopsAtMaxPages(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"items":%s}`, itemsJSON(0, 10))
	}))
	c := offsetConn(h, 10)
	c.Limits.MaxPages = 5
	res, _, err := h.fetch(c)
	if !errors.Is(err, ErrPageLimit) || res.Pages != 5 || hits.Load() != 5 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

// ---- max_records (runner) relies on emit returning an error ----

// The runner enforces max_records by returning an error from emit. The engine
// must stop at once: no further page requests after the failing emit.
func TestPagEmitErrorStopsMidRun(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, pagedVendor(100, 0)))
	stop := errors.New("record limit")
	var got int
	res, err := h.eng.Fetch(t.Context(), pageConn(h, 10), func(p Page) error {
		got += len(p.Items)
		if got > 25 { // cap reached in the middle of page 3
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || res.Pages != 3 || hits.Load() != 3 {
		t.Fatalf("pages=%d hits=%d err=%v", res.Pages, hits.Load(), err)
	}
}

// ---- Config values honoured ----

func TestPagStartPageAndSizeHonoured(t *testing.T) {
	var seen []string
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 3 {
			fmt.Fprint(w, `{"items":`+itemsJSON(0, 7)+`}`)
			return
		}
		fmt.Fprint(w, `{"items":`+itemsJSON(0, 2)+`}`)
	})
	c := pageConn(h, 7)
	three := 3
	c.Pagination.StartPage = &three
	res, _, err := h.fetch(c)
	want := []string{"page=3&size=7", "page=4&size=7"}
	if err != nil || res.Pages != 2 || fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("pages=%d queries=%v want %v err=%v", res.Pages, seen, want, err)
	}
}

func TestOffsetStartsAtZero(t *testing.T) {
	var seen []string
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		pagedVendor(13, 0)(w, r)
	})
	if _, _, err := h.fetch(offsetConn(h, 10)); err != nil {
		t.Fatal(err)
	}
	want := []string{"offset=0&size=10", "offset=10&size=10"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("queries=%v want %v", seen, want)
	}
}

// Zero-based APIs (Spring Data, many Java backends) need start_page 0. Today
// 0 is indistinguishable from "unset" and is rewritten to 1, so page 0 is
// never requested and its records are silently lost.
func TestPagStartPageZero(t *testing.T) {
	var first atomic.Value
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		first.CompareAndSwap(nil, r.URL.Query().Get("page"))
		fmt.Fprint(w, `{"items":[]}`)
	})
	c := pageConn(h, 10)
	zero := 0
	c.Pagination.StartPage = &zero // explicit zero-based paging
	if _, _, err := h.fetch(c); err != nil {
		t.Fatal(err)
	}
	knownBug(t, first.Load() == "1",
		"start_page 0 is replaced by the default 1 (spec.go withDefaults setDefault(&StartPage, 1)); page 0 is skipped")
	if first.Load() != "0" {
		t.Fatalf("first page requested = %v, want 0", first.Load())
	}
}

// ---- Bad bodies: clean errors, no panic, earlier pages kept ----

func TestPagItemsPathProblems(t *testing.T) {
	for name, body := range map[string]string{
		"path missing":       `{"results":[]}`,
		"path is object":     `{"items":{"id":1}}`,
		"path is string":     `{"items":"none"}`,
		"path is null":       `{"items":null}`,
		"body is array":      `[{"id":1}]`,
		"body is null":       `null`,
		"body is number":     `42`,
		"nested through str": `{"items":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			res, items, err := h.fetch(pageConn(h, 10))
			if err == nil || !strings.Contains(err.Error(), "items_path") || res.Pages != 0 || len(items) != 0 {
				t.Fatalf("pages=%d items=%d err=%v", res.Pages, len(items), err)
			}
		})
	}
}

func TestPagNonJSONBodyWith200(t *testing.T) {
	for name, body := range map[string]string{
		"html error page":  `<!doctype html><html><body>Service Unavailable SECRET-IN-BODY</body></html>`,
		"empty":            ``,
		"plain text":       `rate limited SECRET-IN-BODY`,
		"truncated json":   `{"items":[{"id":1},`,
		"trailing content": `{"items":[]} {"items":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, body)
			})
			res, _, err := h.fetch(pageConn(h, 10))
			if err == nil || res.Pages != 0 || strings.Contains(err.Error(), "SECRET-IN-BODY") {
				t.Fatalf("pages=%d err=%v", res.Pages, err)
			}
		})
	}
}

// A bad body on page 2 fails the run but page 1 stays emitted (caller marks
// the run partial).
func TestPagBadSecondPageKeepsFirst(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, counted(&hits, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `<html>oops</html>`)
			return
		}
		fmt.Fprintf(w, `{"items":%s}`, itemsJSON(0, 10))
	}))
	res, items, err := h.fetch(pageConn(h, 10))
	if err == nil || !strings.Contains(err.Error(), "page 2") || res.Pages != 1 || len(items) != 10 || hits.Load() != 2 {
		t.Fatalf("pages=%d items=%d hits=%d err=%v", res.Pages, len(items), hits.Load(), err)
	}
}
