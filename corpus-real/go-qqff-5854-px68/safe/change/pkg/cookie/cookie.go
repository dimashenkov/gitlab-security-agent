









package cookie

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"


	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"go.uber.org/zap"
)

const maxCookieSize = 4000
const maxCookieParts = 32

var log *zap.SugaredLogger
var sameSite http.SameSite


func Configure() {
	log = cfg.Logging.Logger
	sameSite = SameSite()
}


func SetCookie(w http.ResponseWriter, r *http.Request, val string) {
	setCookie(w, r, val, cfg.Cfg.Cookie.MaxAge*60)
}

func setCookie(w http.ResponseWriter, r *http.Request, val string, maxAge int) {

	domain := domains.Matches(r.Host)

	if cfg.Cfg.Cookie.Domain != "" {
		domain = cfg.Cfg.Cookie.Domain
	}
	log.Debugf("setting the cookie domain to %v", domain)


	cookie := http.Cookie{
		Name:     cfg.Cfg.Cookie.Name,
		Value:    val,
		Path:     "/",
		Domain:   domain,
		MaxAge:   maxAge,
		Secure:   cfg.Cfg.Cookie.Secure,
		HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
		SameSite: sameSite,
	}
	cookieSize := len(cookie.String())



	if cookieSize > maxCookieSize {

		log.Warnf("cookie size: %d.  cookie sizes over ~4093 bytes(depending on the browser and platform) have shown to cause issues or simply aren't supported.", cookieSize)
		emptyCookie := cookie
		emptyCookie.Value = ""
		emptyCookieSize := len(emptyCookie.String())
		cookieParts := splitCookie(val, maxCookieSize-emptyCookieSize)
		for i, cookiePart := range cookieParts {

			cookie.Name = fmt.Sprintf("%s_%dof%d", cfg.Cfg.Cookie.Name, i+1, len(cookieParts))
			cookie.Value = cookiePart
			http.SetCookie(w, &cookie)
		}
	} else {
		http.SetCookie(w, &cookie)
	}
}


func Cookie(r *http.Request) (string, error) {

	var cookieParts []string
	var numParts = -1

	var err error
	cookies := r.Cookies()



	for _, cookie := range cookies {
		if cookie.Name == cfg.Cfg.Cookie.Name {
			return cookie.Value, nil
		}
		cookieUnder := fmt.Sprintf("%s_", cfg.Cfg.Cookie.Name)
		if strings.HasPrefix(cookie.Name, cookieUnder) {
			log.Debugw("cookie",
				"cookieName", cookie.Name,
				"cookieValue", cookie.Value,
			)
			xOFy := strings.Replace(cookie.Name, cookieUnder, "", 1)
			xyArray := strings.Split(xOFy, "of")
			if numParts == -1 {
				if numParts, err = strconv.Atoi(xyArray[1]); err != nil {
					return "", fmt.Errorf("multipart cookie fail: %s", err)
				}
				if numParts < 1 || numParts > maxCookieParts {
					return "", fmt.Errorf("multipart cookie fail: invalid part count %s", xOFy)
				}
				log.Debugf("make cookieParts of size %d", numParts)
				cookieParts = make([]string, numParts)
			}
			var i int
			if i, err = strconv.Atoi(xyArray[0]); err != nil {
				return "", fmt.Errorf("multipart cookie fail: %s", err)
			}
			if i > numParts {
				return "", fmt.Errorf("multipart cookie fail: invalid part count %s", xOFy)
			}
			cookieParts[i-1] = cookie.Value
		}

	}

	combinedCookieStr := strings.Join(cookieParts, "")
	if combinedCookieStr == "" {
		return "", errors.New("cookie token empty")
	}

	log.Debugw("combined cookie",
		"cookieValue", combinedCookieStr,
	)
	return combinedCookieStr, err
}


func ClearCookie(w http.ResponseWriter, r *http.Request) {
	cookies := r.Cookies()
	domain := domains.Matches(r.Host)

	if cfg.Cfg.Cookie.Domain != "" {
		domain = cfg.Cfg.Cookie.Domain
		log.Debugf("setting the cookie domain to %v", domain)
	}

	for _, cookie := range cookies {
		if strings.HasPrefix(cookie.Name, cfg.Cfg.Cookie.Name) {
			log.Debugf("deleting cookie: %s", cookie.Name)
			http.SetCookie(w, &http.Cookie{
				Name:   cookie.Name,
				Value:  "delete",
				Path:   "/",
				Domain: domain,

				Expires:  time.Unix(0, 0),
				Secure:   cfg.Cfg.Cookie.Secure,
				HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
			})
		}
	}
}




func SameSite() http.SameSite {
	sameSite := http.SameSite(0)
	if cfg.Cfg.Cookie.SameSite != "" {
		switch strings.ToLower(cfg.Cfg.Cookie.SameSite) {
		case "lax":
			sameSite = http.SameSiteLaxMode
		case "strict":
			sameSite = http.SameSiteStrictMode
		case "none":
			if !cfg.Cfg.Cookie.Secure {
				log.Error("SameSite cookie attribute with sameSite=none should also be specified with secure=true.")
			}
			sameSite = http.SameSiteNoneMode
		}
	}
	return sameSite
}


func splitCookie(longString string, maxLen int) []string {
	splits := make([]string, 0)

	var l, r int
	for l, r = 0, maxLen; r < len(longString); l, r = r, r+maxLen {
		for !utf8.RuneStart(longString[r]) {
			r--
		}
		splits = append(splits, longString[l:r])
	}
	splits = append(splits, longString[l:])
	return splits
}
