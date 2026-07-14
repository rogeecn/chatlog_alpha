package send

import (
	"strings"
	"testing"
)

func TestRequestNormalizedPrivateAndGroupAreExclusive(t *testing.T) {
	_, err := (Request{
		Operation:   OperationSend,
		TargetType:  TargetPrivate,
		MessageType: MessageText,
		UserID:      "wxid_demo",
		GroupID:     "123@chatroom",
		Content:     "hello",
		AcceptRisk:  true,
	}).Normalized()
	if err == nil {
		t.Fatal("expected ambiguous target to be rejected")
	}
}

func TestRequestNormalizedGroupMention(t *testing.T) {
	req, err := (Request{
		Operation:   OperationSend,
		TargetType:  TargetGroup,
		MessageType: MessageText,
		GroupID:     "123@chatroom",
		Content:     "收到",
		AtUser:      " wxid_a，wxid_b,wxid_a ",
		AtName:      "@小明",
		AcceptRisk:  true,
	}).Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if req.Receiver() != "123@chatroom" {
		t.Fatalf("unexpected receiver %q", req.Receiver())
	}
	if req.AtUser != "wxid_a,wxid_b" {
		t.Fatalf("unexpected mention list %q", req.AtUser)
	}
	if req.Content != "@小明\u2005收到" {
		t.Fatalf("unexpected visible mention %q", req.Content)
	}
}

func TestRequestNormalizedRejectsBadGroupID(t *testing.T) {
	_, err := (Request{
		Operation:   OperationProbe,
		TargetType:  TargetGroup,
		MessageType: MessageText,
		GroupID:     "wxid_not_a_group",
	}).Normalized()
	if err == nil {
		t.Fatal("expected group suffix validation")
	}
}

func TestProbeDoesNotRequirePayloadOrRisk(t *testing.T) {
	req, err := (Request{
		Operation:   OperationProbe,
		TargetType:  TargetPrivate,
		MessageType: MessageImage,
		UserID:      "filehelper",
	}).Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if req.AcceptRisk {
		t.Fatal("probe should not mutate risk acknowledgement")
	}
}

func TestRequestNormalizedValidatesReceiverEncodingAndLimit(t *testing.T) {
	for _, userID := range []string{"文件传输助手", strings.Repeat("a", MaxReceiverBytes+1)} {
		_, err := (Request{
			Operation:   OperationProbe,
			TargetType:  TargetPrivate,
			MessageType: MessageText,
			UserID:      userID,
		}).Normalized()
		if err == nil {
			t.Fatalf("expected receiver %q to be rejected", userID)
		}
	}
	longGroup := strings.Repeat("1", 40) + "@chatroom"
	req, err := (Request{
		Operation:   OperationProbe,
		TargetType:  TargetGroup,
		MessageType: MessageImage,
		GroupID:     longGroup,
	}).Normalized()
	if err != nil {
		t.Fatalf("long ASCII group receiver should use the long-string profile: %v", err)
	}
	if req.Receiver() != longGroup {
		t.Fatalf("unexpected receiver %q", req.Receiver())
	}
}
