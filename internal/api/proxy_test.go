package api

import (
	"net/http/httptest"
	"testing"
)

func TestProxySecretGate(t *testing.T) {
	a := &API{ProxySecret: "0123456789abcdef0123456789abcdef"}
	req := func(path, secret string) (*httptest.ResponseRecorder, bool, string, string) {
		r := httptest.NewRequest("GET", "https://api.internal"+path, nil)
		r.RemoteAddr = "172.30.0.9:5555"
		r.Header.Set("X-CB-Client-IP", "203.0.113.7")
		r.Header.Set("X-CB-Forwarded-Host", "app.example.com")
		if secret != "" {
			r.Header.Set("X-CB-Proxy-Secret", secret)
		}
		w := httptest.NewRecorder()
		ok := a.fromProxy(w, r)
		if r.Header.Get("X-CB-Proxy-Secret") != "" {
			t.Error("secret must not reach handlers")
		}
		return w, ok, r.RemoteAddr, r.Host
	}
	if w, ok, ip, host := req("/configs", ""); ok || w.Code != 403 || ip != "172.30.0.9:5555" || host != "api.internal" {
		t.Fatal("direct request must be refused and its headers ignored", w.Code, ip, host)
	}
	if _, ok, _, _ := req("/configs", "wrong-wrong-wrong-wrong-wrong-wrong"); ok {
		t.Fatal("wrong secret accepted")
	}
	if _, ok, ip, _ := req("/health", ""); !ok || ip != "172.30.0.9:5555" {
		t.Fatal("health must stay open without trusting headers")
	}
	if _, ok, ip, host := req("/configs", a.ProxySecret); !ok || ip != "203.0.113.7:0" || host != "app.example.com" {
		t.Fatal("proxied request must use forwarded IP and host", ip, host)
	}
	a.ProxySecret = ""
	if _, ok, ip, host := req("/configs", ""); !ok || ip != "172.30.0.9:5555" || host != "api.internal" {
		t.Fatal("without a secret, forwarded headers must be ignored")
	}
}
