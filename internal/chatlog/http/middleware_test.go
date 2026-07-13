package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func runCORSTest(t *testing.T, bind, host, origin, method string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware(bind))
	router.Any("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(method, "http://"+host+"/test", nil)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestCORSMiddlewareAllowsLoopbackOriginWithoutWildcard(t *testing.T) {
	recorder := runCORSTest(t, "127.0.0.1:5030", "127.0.0.1:5030", "http://localhost:3000", http.MethodGet)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("allow origin = %q", got)
	}
}

func TestCORSMiddlewareRejectsCrossSiteOriginAndReboundHost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		host   string
		origin string
	}{
		{name: "cross-site origin", host: "127.0.0.1:5030", origin: "https://example.com"},
		{name: "rebound host", host: "example.com", origin: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := runCORSTest(t, "127.0.0.1:5030", tc.host, tc.origin, http.MethodGet)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", recorder.Code)
			}
		})
	}
}

func TestCORSMiddlewareSupportsExplicitPrivateNetworkBinding(t *testing.T) {
	recorder := runCORSTest(t, "0.0.0.0:5030", "192.168.1.20:5030", "http://192.168.1.20:5030", http.MethodPost)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}
