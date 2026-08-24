package server

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/axllent/mailpit/internal/logger"
)

var (

	AccessControlAllowOrigin string


	corsAllowOrigins = make(map[string]bool)
)



func asciiFoldString(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		b[i] = toLowerASCIIFold(s[i])
	}
	return string(b)
}



func toLowerASCIIFold(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}


func corsOriginAccessControl(r *http.Request) bool {
	origin := r.Header["Origin"]

	if len(origin) != 0 {
		u, err := url.Parse(origin[0])
		if err != nil {
			logger.Log().Errorf("[cors] origin parse error: %v", err)
			return false
		}

		_, allAllowed := corsAllowOrigins["*"]

		if asciiFoldString(u.Host) == asciiFoldString(r.Host) || allAllowed {
			return true
		}



		originHostFold := asciiFoldString(u.Host)
		if corsAllowOrigins[originHostFold] {
			return true
		}

		logger.Log().Warnf("[cors] blocking request from unauthorized origin: %s", u.Host)

		return false
	}

	return true
}




func setCORSOrigins() {
	corsAllowOrigins = make(map[string]bool)

	hosts := extractOrigins(AccessControlAllowOrigin)
	for _, host := range hosts {
		corsAllowOrigins[asciiFoldString(host)] = true
	}

	if len(corsAllowOrigins) == 0 {
		return
	}

	if _, wildCard := corsAllowOrigins["*"]; wildCard {

		corsAllowOrigins = make(map[string]bool)
		corsAllowOrigins["*"] = true
		logger.Log().Info("[cors] all origins are allowed due to wildcard \"*\"")
	} else {
		keys := make([]string, 0)
		for k := range corsAllowOrigins {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		logger.Log().Infof("[cors] allowed API origins: %v", strings.Join(keys, ", "))
	}
}


func extractOrigins(str string) []string {
	origins := make([]string, 0)
	s := strings.TrimSpace(str)
	if s == "" {
		return origins
	}

	hosts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' '
	})

	for _, host := range hosts {
		h := strings.TrimSpace(host)
		if h != "" {
			if h == "*" {
				return []string{"*"}
			}

			if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
				h = "http://" + h
			}

			u, err := url.Parse(h)
			if err != nil || u.Hostname() == "" || strings.Contains(h, "*") {
				logger.Log().Warnf("[cors] invalid CORS origin \"%s\", ignoring", h)
				continue
			}



			origins = append(origins, u.Host)
		}
	}

	sort.Strings(origins)

	return origins
}
