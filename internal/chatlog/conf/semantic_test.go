package conf

import (
	"reflect"
	"testing"
)

func TestNormalizeSemanticConfigCleansIndexChatrooms(t *testing.T) {
	cfg := NormalizeSemanticConfig(SemanticConfig{
		IndexChatrooms: []string{" room-a@chatroom ", "", "room-a@chatroom", "wxid_b"},
	})
	want := []string{"room-a@chatroom", "wxid_b"}
	if !reflect.DeepEqual(cfg.IndexChatrooms, want) {
		t.Fatalf("IndexChatrooms = %#v, want %#v", cfg.IndexChatrooms, want)
	}
	if !SemanticTalkerAllowed(cfg, "room-a@chatroom") {
		t.Fatal("whitelisted talker was rejected")
	}
	if SemanticTalkerAllowed(cfg, "room-c@chatroom") {
		t.Fatal("talker outside whitelist was accepted")
	}
}

func TestSemanticTalkerAllowedWithoutWhitelist(t *testing.T) {
	if !SemanticTalkerAllowed(SemanticConfig{}, "any-talker") {
		t.Fatal("empty whitelist should allow all talkers")
	}
}
