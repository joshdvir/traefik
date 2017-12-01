package middlewares

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/whitelist"
	"github.com/pkg/errors"
	"github.com/urfave/negroni"
)

// IPWhiteLister is a middleware that provides Checks of the Requesting IP against a set of Whitelists
type IPWhiteLister struct {
	handler     negroni.Handler
	whiteLister *whitelist.IP
}

// NewIPWhitelister builds a new IPWhiteLister given a list of CIDR-Strings to whitelist
func NewIPWhitelister(whitelistStrings []string) (*IPWhiteLister, error) {

	if len(whitelistStrings) == 0 {
		return nil, errors.New("no whitelists provided")
	}

	whiteLister := IPWhiteLister{}

	ip, err := whitelist.NewIP(whitelistStrings, false)
	if err != nil {
		return nil, fmt.Errorf("parsing CIDR whitelist %s: %v", whitelistStrings, err)
	}
	whiteLister.whiteLister = ip

	whiteLister.handler = negroni.HandlerFunc(whiteLister.handle)
	log.Debugf("configured %u IP whitelists: %s", len(whitelistStrings), whitelistStrings)

	return &whiteLister, nil
}

func (wl *IPWhiteLister) handle(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ipAddress, _, err := ipFromRemoteAddr(r)
	if err != nil {
		log.Warnf("unable to parse remote-address from header: %s - rejecting", r.RemoteAddr)
		reject(w)
		return
	}

	allowed, ip, err := wl.whiteLister.Contains(ipAddress)
	if err != nil {
		log.Debugf("source-IP %s matched none of the whitelists - rejecting", ipAddress)
		reject(w)
		return
	}

	if allowed {
		log.Debugf("source-IP %s matched whitelist %s - passing", ipAddress, wl.whiteLister)
		next.ServeHTTP(w, r)
		return
	}

	log.Debugf("source-IP %s matched none of the whitelists - rejecting", ip)
	reject(w)
}

func (wl *IPWhiteLister) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	wl.handler.ServeHTTP(rw, r, next)
}

func reject(w http.ResponseWriter) {
	statusCode := http.StatusForbidden

	w.WriteHeader(statusCode)
	w.Write([]byte(http.StatusText(statusCode)))
}

func ipFromRemoteAddr(req *http.Request) (*net.IP, error) {
	hdr := req.Header
	// First check the X-Forwarded-For header for requests via proxy.
	hdrForwardedFor := hdr.Get("X-Forwarded-For")
	if hdrForwardedFor != "" {
		// X-Forwarded-For can be a csv of IPs in case of multiple proxies.
		// Use the first valid one.
		parts := strings.Split(hdrForwardedFor, ",")
		for _, part := range parts {
			ip := net.ParseIP(strings.TrimSpace(part))
			if ip != nil {
				return &ip, nil
			}
		}
	}

	// Try the X-Real-Ip header.
	hdrRealIP := hdr.Get("X-Real-Ip")
	if hdrRealIP != "" {
		ip := net.ParseIP(hdrRealIP)
		if ip != nil {
			return &ip, nil
		}
	}

	// Fallback to Remote Address in request, which will give the correct client IP when there is no proxy.
	// Remote Address in Go's HTTP server is in the form host:port so we need to split that first.
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("can't extract IP/Port from address %s: %s", req.RemoteAddr, err)
	}

	// Fallback if Remote Address was just IP.
	userIP := net.ParseIP(ip)
	if userIP == nil {
		return nil, fmt.Errorf("can't parse IP from address %s", ip)
	}

	return &userIP, nil
}

// func (whitelister *IPWhitelister) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
// 	whitelister.handler.ServeHTTP(rw, r, next)
// }
