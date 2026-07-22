package windows

import "testing"

func TestIsWeixinChildCommandLine(t *testing.T) {
	tests := []struct {
		commandLine string
		wantChild   bool
	}{
		{commandLine: `C:\\Weixin.exe`, wantChild: false},
		{commandLine: `C:\\Weixin.exe --scene=login`, wantChild: false},
		{commandLine: `C:\\Weixin.exe --type=wxutility --lang=zh-CN`, wantChild: true},
	}
	for _, tc := range tests {
		if got := isWeixinChildCommandLine(tc.commandLine); got != tc.wantChild {
			t.Fatalf("isWeixinChildCommandLine(%q) = %v, want %v", tc.commandLine, got, tc.wantChild)
		}
	}
}
