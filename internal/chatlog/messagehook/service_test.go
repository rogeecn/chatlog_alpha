package messagehook

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionInForwardWhitelistMatchesIDOrDisplayName(t *testing.T) {
	contacts := map[string]struct{}{"wxid_friend": {}}
	chatrooms := map[string]struct{}{"项目群": {}}

	if !sessionInForwardWhitelist("wxid_friend", "好友", contacts, chatrooms) {
		t.Fatal("contact ID should match")
	}
	if !sessionInForwardWhitelist("123@chatroom", "项目群", contacts, chatrooms) {
		t.Fatal("chatroom display name should match")
	}
	if sessionInForwardWhitelist("other@chatroom", "其他群", contacts, chatrooms) {
		t.Fatal("unlisted session should be skipped")
	}
}

func TestFailedPostDeliveryIsRetried(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	service := &Service{
		httpClient:  server.Client(),
		pendingPost: make(map[string]pendingPostDelivery),
	}
	evt := Event{Talker: "room", TriggerSeq: 7, RuleType: "keyword", RuleLabel: "build"}
	result := service.deliverPost(server.URL, evt)
	if result.Success {
		t.Fatal("first delivery should fail")
	}
	evt.Deliveries = append(evt.Deliveries, result)
	service.queuePostRetry(server.URL, evt)
	service.retryPendingPosts(time.Now().Add(maxPostRetryDelay))
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(service.pendingPost) != 0 {
		t.Fatalf("successful retry was retained: %#v", service.pendingPost)
	}
}
