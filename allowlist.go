package main

import (
        "log/slog"
        "net"
        "strconv"
        "strings"
)

// Allowlist filtra destinos (host:port) para evitar que el relay se
// convierta en un open proxy si el secreto compartido se filtra.
//
// Formato de reglas (separadas por coma en ALLOWLIST):
//
//      host:port        host exacto, puerto exacto
//      host:*           host exacto, cualquier puerto
//      *.domain:port    cualquier subdominio de domain, puerto exacto
//      *.domain:*       cualquier subdominio, cualquier puerto
//      CIDR:port        red IPv4/IPv6 en notación CIDR, puerto exacto
//      CIDR:*           red CIDR, cualquier puerto
//
// Ejemplos para Telegram:
//
//      149.154.160.0/20:*   (rango principal de DCs de Telegram)
//      91.108.0.0/16:*      (rango secundario)
//      api.telegram.org:443
//
// Si la lista está vacía se permite todo (backward compat) con un warning.
type Allowlist struct {
        rules []allowRule
}

type allowRule struct {
        host     string    // host exacto o sufijo (si wildcard)
        wildcard bool      // true si la regla era *.domain
        port     int       // 0 = cualquier puerto
        ipnet    *net.IPNet // no nil si la regla era CIDR
}

func ParseAllowlist(patterns []string) *Allowlist {
        a := &Allowlist{}
        for _, p := range patterns {
                p = strings.TrimSpace(p)
                if p == "" {
                        continue
                }
                // Split en el ÚLTIMO colon para soportar IPv6 (2001:b28::/32:*)
                idx := strings.LastIndex(p, ":")
                if idx < 0 {
                        slog.Warn("allowlist: regla sin puerto, ignorada", "rule", p)
                        continue
                }
                host, portStr := strings.TrimSpace(p[:idx]), strings.TrimSpace(p[idx+1:])
                r := allowRule{}
                if strings.HasPrefix(host, "*.") {
                        r.wildcard = true
                        r.host = strings.TrimPrefix(host, "*.")
                } else {
                        r.host = host
                }
                // Soporte CIDR: "149.154.160.0/20" o "2001:b28::/32".
                if strings.Contains(host, "/") {
                        _, ipnet, err := net.ParseCIDR(host)
                        if err != nil {
                                slog.Warn("allowlist: CIDR inválido, ignorado", "rule", p)
                                continue
                        }
                        r.ipnet = ipnet
                }
                if portStr != "*" {
                        r.port, _ = strconv.Atoi(portStr)
                }
                a.rules = append(a.rules, r)
        }
        if len(a.rules) > 0 {
                slog.Info("allowlist parseado", "rules", len(a.rules))
        }
        return a
}

// Allow decide si un destino está permitido.
func (a *Allowlist) Allow(host string, port int) bool {
        if a == nil || len(a.rules) == 0 {
                return true
        }
        host = strings.TrimSpace(host)
        ip := net.ParseIP(host)
        for _, r := range a.rules {
                if r.port != 0 && r.port != port {
                        continue
                }
                if r.ipnet != nil {
                        if ip != nil && r.ipnet.Contains(ip) {
                                return true
                        }
                        continue
                }
                if r.wildcard {
                        if host == r.host || strings.HasSuffix(host, "."+r.host) {
                                return true
                        }
                } else if r.host == host {
                        return true
                }
        }
        return false
}
