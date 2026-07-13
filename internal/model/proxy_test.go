package model

import "testing"

func TestRefreshProxyFields(t *testing.T) {
	message := &Message{
		Type: MessageTypeImage,
		Contents: map[string]interface{}{
			"md5": "abc123",
		},
	}
	message.RefreshProxyFields()
	if got := message.Contents["proxyType"]; got != "image" {
		t.Fatalf("proxyType = %#v", got)
	}
	if got := message.Contents["proxyUrl"]; got != "/image/abc123" {
		t.Fatalf("proxyUrl = %#v", got)
	}
	if got := message.Contents["resolved"]; got != true {
		t.Fatalf("resolved = %#v", got)
	}
}

func TestRecordAssetMetadata(t *testing.T) {
	item := DataItem{DataType: "8", DataTitle: "report.pdf", DataSize: "42"}
	item.SetResolvedProxy("file", "deadbeef", "hardlink_by_name_size")
	asset := item.ToAsset("1.2")
	if asset.ProxyURL != "/file/deadbeef" || asset.Size != 42 || !asset.Resolved {
		t.Fatalf("unexpected asset: %#v", asset)
	}
}
