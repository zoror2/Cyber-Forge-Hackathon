package app

import (
	"testing"
)

func TestDevOverridesNeverEnableProduction(t *testing.T) {
	for _, env := range []map[string]string{{"CB_DEV_ALLOW_PRIVATE": "127.0.0.0/8"}, {"CB_DEV_CA_FILE": "x"}, {"CB_DEV_ALLOW_HTTP": "1"}, {"CB_ENV": "dev", "CB_DEV_ALLOW_HTTP": "1"}, {"CB_ENV": "dev", "CB_DEV_ALLOW_PRIVATE": "0.0.0.0/0"}} {
		if _, e := Policy(func(k string) string { return env[k] }); e == nil {
			t.Fatal("unsafe override accepted")
		}
	}
	if p, e := Policy(func(string) string { return "" }); e != nil || p.AllowHTTP || len(p.AllowPrivate) > 0 || p.RootCAs != nil {
		t.Fatal("production policy weakened")
	}
}
