package ai

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"configbridge/internal/egress"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Many vendor docs portals build the page with JavaScript, so a plain
// download has no API text. The renderer opens such a page in a headless
// Chrome that runs in its OWN container (never inside the API process). The
// API drives it over the DevTools protocol and intercepts every request the
// page makes: each must pass the production egress rules (https, port 443,
// every resolved IP public). Note: Chrome resolves DNS again after our check,
// so the renderer container must also sit on a network without access to
// internal services; the interception is the second line, not the only one.

// RenderedPage is what the docs page looked like after its scripts ran.
type RenderedPage struct {
	HTML  string
	Text  string
	Specs []string // OpenAPI-looking files the page downloaded (.json/.yaml)
}

const maxRenderedBytes = 16 << 20

// NewRenderer connects to the renderer container's DevTools endpoint
// (CB_DOC_RENDERER, e.g. http://renderer:9222).
func NewRenderer(devtools string) (func(context.Context, string) (*RenderedPage, error), error) {
	u, e := url.Parse(devtools)
	if e != nil || (u.Scheme != "http" && u.Scheme != "ws") || u.Hostname() == "" {
		return nil, fmt.Errorf("CB_DOC_RENDERER must be the renderer's http:// or ws:// DevTools address")
	}
	return func(ctx context.Context, raw string) (*RenderedPage, error) {
		if !publicDocURL(raw) {
			return nil, ErrDocumentation
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		select {
		case documentationSlots <- struct{}{}:
			defer func() { <-documentationSlots }()
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: documentation reader busy", ErrDocumentation)
		}
		// Chrome refuses DevTools requests whose Host is a name, not an IP.
		addr := *u
		if ips, e := net.DefaultResolver.LookupHost(ctx, u.Hostname()); e == nil && len(ips) > 0 {
			addr.Host = net.JoinHostPort(ips[0], u.Port())
		}
		actx, acancel := chromedp.NewRemoteAllocator(ctx, addr.String())
		defer acancel()
		tctx, tcancel := chromedp.NewContext(actx)
		defer tcancel()

		var mu sync.Mutex
		specs := []string{}
		chromedp.ListenTarget(tctx, func(ev any) {
			paused, ok := ev.(*fetch.EventRequestPaused)
			if !ok {
				return
			}
			go func() {
				exec := cdp.WithExecutor(tctx, chromedp.FromContext(tctx).Target)
				if !renderAllowed(tctx, paused.Request.URL, paused.ResourceType) {
					_ = fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient).Do(exec)
					return
				}
				if specFile(paused.Request.URL) {
					mu.Lock()
					if len(specs) < 5 {
						specs = append(specs, strings.SplitN(paused.Request.URL, "?", 2)[0])
					}
					mu.Unlock()
				}
				_ = fetch.ContinueRequest(paused.RequestID).Do(exec)
			}()
		})
		var html, text string
		e := chromedp.Run(tctx,
			fetch.Enable(),
			chromedp.Navigate(raw),
			chromedp.WaitReady("body", chromedp.ByQuery),
			chromedp.Sleep(2*time.Second), // let the docs app fetch and draw its content
			chromedp.OuterHTML("html", &html, chromedp.ByQuery),
			chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &text),
		)
		if e != nil {
			return nil, fmt.Errorf("%w: the documentation page could not be rendered", ErrDocumentation)
		}
		if len(html) > maxRenderedBytes {
			html = html[:maxRenderedBytes]
		}
		mu.Lock()
		defer mu.Unlock()
		return &RenderedPage{HTML: html, Text: compact(text), Specs: append([]string(nil), specs...)}, nil
	}, nil
}

// renderAllowed applies the production egress policy to one browser request.
func renderAllowed(ctx context.Context, raw string, kind network.ResourceType) bool {
	switch kind {
	case network.ResourceTypeImage, network.ResourceTypeMedia, network.ResourceTypeFont:
		return false // not needed for API text; less traffic
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	p := egress.Policy{}
	if p.CheckURL(u) != nil {
		return false
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if e != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if p.CheckIP(ip.Unmap()) != nil {
			return false
		}
	}
	return true
}
