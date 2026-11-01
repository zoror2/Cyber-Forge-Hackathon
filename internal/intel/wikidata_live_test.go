package intel

import (
	"context"
	"os"
	"strings"
	"testing"
)

// CB_LIVE_INTEL=1 LIVE_VENDORS="Cisco;Atlassian" go test -v -run TestLiveSubsidiaries ./internal/intel
func TestLiveSubsidiaries(t *testing.T) {
	if os.Getenv("CB_LIVE_INTEL") != "1" {
		t.Skip("set CB_LIVE_INTEL=1")
	}
	for _, v := range strings.Split(os.Getenv("LIVE_VENDORS"), ";") {
		root, subs, e := Subsidiaries(context.Background(), v)
		names := []string{}
		for _, s := range subs {
			names = append(names, s.Name+"("+s.Since+")")
		}
		t.Logf("%s -> %s %s err=%v subsidiaries=%d %v", v, root.Name, root.QID, e, len(subs), names)
	}
}
