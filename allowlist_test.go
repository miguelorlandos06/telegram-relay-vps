package main

import "testing"

func TestAllowlistEmptyAllowsAll(t *testing.T) {
	a := ParseAllowlist(nil)
	if !a.Allow("anything.example", 9999) {
		t.Fatal("allowlist vacío debe permitir todo")
	}
}

func TestAllowlistExactHostPort(t *testing.T) {
	a := ParseAllowlist([]string{"1.2.3.4:443", "api.example.com:80"})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"1.2.3.4", 443, true},
		{"1.2.3.4", 80, false},  // puerto no permitido
		{"1.2.3.5", 443, false}, // host no permitido
		{"api.example.com", 80, true},
		{"api.example.com", 443, false},
		{"other.example.com", 80, false},
	}
	for _, c := range cases {
		if got := a.Allow(c.host, c.port); got != c.want {
			t.Fatalf("Allow(%q,%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestAllowlistWildcardAndStarPort(t *testing.T) {
	a := ParseAllowlist([]string{"*.example.com:*", "10.0.0.0:53"})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"api.example.com", 443, true},
		{"sub.api.example.com", 8080, true},
		{"example.com", 80, true}, // host == suffix base
		{"notexample.com", 80, false},
		{"10.0.0.0", 53, true},
		{"10.0.0.1", 53, false},
	}
	for _, c := range cases {
		if got := a.Allow(c.host, c.port); got != c.want {
			t.Fatalf("Allow(%q,%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestParseAllowlistIgnoresBadRules(t *testing.T) {
	a := ParseAllowlist([]string{"", "  ", "no-port", "good.host:443"})
	if len(a.rules) != 1 {
		t.Fatalf("esperaba 1 regla válida, got %d", len(a.rules))
	}
}

func TestAllowlistCIDR(t *testing.T) {
	a := ParseAllowlist([]string{"149.154.160.0/20:*", "91.108.0.0/16:443", "2001:b28::/32:*"})
	cases := []struct {
		host string
		port int
		want bool
	}{
		// Rango principal Telegram: 149.154.160.0 - 149.154.175.255
		{"149.154.175.50", 443, true},
		{"149.154.167.51", 5222, true},
		{"149.154.160.0", 80, true},
		{"149.154.175.255", 443, true},
		{"149.154.176.0", 443, false}, // fuera del /20
		{"149.155.0.1", 443, false},
		// Rango secundario: solo puerto 443
		{"91.108.56.130", 443, true},
		{"91.108.56.130", 80, false}, // puerto no permitido
		{"91.109.0.1", 443, false},   // fuera del /16
		// IPv6 Telegram
		{"2001:b28:f23d:f001::a", 443, true},
		{"2001:b29::1", 443, false},
		// Hosts no-IP no matchean CIDR aunque se parezcan
		{"149.154.160.0.not-ip", 443, false},
	}
	for _, c := range cases {
		if got := a.Allow(c.host, c.port); got != c.want {
			t.Fatalf("Allow(%q,%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestAllowlistInvalidCIDRIgnored(t *testing.T) {
	a := ParseAllowlist([]string{"999.999.0.0/8:443", "not-a-cidr/99:*"})
	if len(a.rules) != 0 {
		t.Fatalf("reglas CIDR inválidas deben ignorarse, got %d", len(a.rules))
	}
	// Tras ignorar todas las reglas la lista queda vacía: permite todo
	// (mismo comportamiento que una allowlist sin reglas).
	if !a.Allow("1.2.3.4", 443) {
		t.Fatal("lista vacía tras reglas inválidas debe permitir todo")
	}
}
