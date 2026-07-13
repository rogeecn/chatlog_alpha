package chatlog

import "testing"

func TestOptionalActionValues(t *testing.T) {
	if optionalActionBool(false, true) != nil {
		t.Fatal("disabled optional bool should be nil")
	}
	if got := optionalActionBool(true, false); got == nil || *got {
		t.Fatalf("unexpected optional bool: %#v", got)
	}
	if optionalActionInt(false, 10) != nil {
		t.Fatal("disabled optional int should be nil")
	}
	if got := optionalActionInt(true, 10); got == nil || *got != 10 {
		t.Fatalf("unexpected optional int: %#v", got)
	}
}
