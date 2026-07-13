package http

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sjzar/chatlog/internal/chatlog/database"
)

func hostOnly(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" || strings.HasPrefix(hostport, ":") {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(strings.ToLower(host), "[]")
	}
	return strings.Trim(strings.ToLower(hostport), "[]")
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isWildcardHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	return host == "" || host == "0.0.0.0" || host == "::"
}

func isPrivateNetworkHost(host string) bool {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func requestHostAllowed(boundHost, requestHost string) bool {
	if isWildcardHost(boundHost) {
		return true
	}
	if isLoopbackHost(boundHost) {
		return isLoopbackHost(requestHost)
	}
	return isLoopbackHost(requestHost) || strings.EqualFold(boundHost, requestHost)
}

func originAllowed(boundHost, requestHost, origin string) bool {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	originHost := strings.ToLower(u.Hostname())
	if isLoopbackHost(originHost) {
		return true
	}
	if !strings.EqualFold(originHost, requestHost) {
		return false
	}
	if isWildcardHost(boundHost) {
		return isPrivateNetworkHost(originHost)
	}
	return strings.EqualFold(originHost, boundHost)
}

func corsMiddleware(httpAddr string) gin.HandlerFunc {
	boundHost := hostOnly(httpAddr)
	return func(c *gin.Context) {
		requestHost := hostOnly(c.Request.Host)
		if !requestHostAllowed(boundHost, requestHost) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		if origin := c.Request.Header.Get("Origin"); origin != "" {
			if !originAllowed(boundHost, requestHost, origin) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Add("Vary", "Origin")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *Service) checkDBStateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch s.db.State {
		case database.StateInit:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is not ready"})
			c.Abort()
			return
		case database.StateDecrypting:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is decrypting, please wait"})
			c.Abort()
			return
		case database.StateError:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is error: " + s.db.StateMsg})
			c.Abort()
			return
		}

		c.Next()
	}
}
