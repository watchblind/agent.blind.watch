package browse

import (
	"testing"
)

const cannedSystemctl = `UNIT                        LOAD      ACTIVE   SUB     DESCRIPTION
blindwatch-agent.service    loaded    active   running blind.watch agent
cron.service                loaded    active   running Regular background program processing daemon
networking.service          loaded    failed   failed  Raise network interfaces
nginx.service               loaded    active   running A high performance web server and a reverse proxy server
ssh.service                 loaded    inactive dead    OpenBSD Secure Shell server
apparmor.service            loaded    active   exited  Load AppArmor profiles
some.socket                 loaded    active   running Not a service, must be skipped

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

7 loaded units listed.
`

func TestParseListUnits_CannedOutput(t *testing.T) {
	units := parseListUnits(cannedSystemctl)

	wantNames := []string{"apparmor", "cron", "nginx", "networking", "ssh"}
	if len(units) != len(wantNames) {
		t.Fatalf("got %d units %+v, want %d", len(units), units, len(wantNames))
	}
	for i, want := range wantNames {
		if units[i].Name != want {
			t.Errorf("units[%d].Name = %q, want %q (active first, then alphabetical)", i, units[i].Name, want)
		}
	}

	for _, u := range units {
		if u.Name == selfUnitName {
			t.Errorf("agent's own unit %q must be excluded", selfUnitName)
		}
	}

	active := map[string]bool{"apparmor": true, "cron": true, "nginx": true, "networking": false, "ssh": false}
	for _, u := range units {
		if u.Active != active[u.Name] {
			t.Errorf("unit %q Active = %v, want %v", u.Name, u.Active, active[u.Name])
		}
	}

	descs := map[string]string{
		"cron":       "Regular background program processing daemon",
		"networking": "Raise network interfaces",
		"ssh":        "OpenBSD Secure Shell server",
	}
	for _, u := range units {
		if want, ok := descs[u.Name]; ok && u.Description != want {
			t.Errorf("unit %q Description = %q, want %q", u.Name, u.Description, want)
		}
	}
}

func TestParseListUnits_StopsAtLegend(t *testing.T) {
	units := parseListUnits(cannedSystemctl)
	for _, u := range units {
		if u.Name == "LOAD" || u.Name == "ACTIVE" || u.Name == "SUB" {
			t.Errorf("legend line leaked into units: %+v", u)
		}
	}
}

func TestParseListUnits_Empty(t *testing.T) {
	if units := parseListUnits(""); len(units) != 0 {
		t.Errorf("empty output should yield no units, got %+v", units)
	}
	if units := parseListUnits("0 loaded units listed.\n"); len(units) != 0 {
		t.Errorf("footer-only output should yield no units, got %+v", units)
	}
}
