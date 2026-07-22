package http

import (
	"testing"

	"github.com/sjzar/chatlog/internal/model"
)

func TestEnrichRecordInfoFlattensNestedAssets(t *testing.T) {
	record := &model.RecordInfo{DataList: model.DataList{DataItems: []model.DataItem{
		{DataType: "2", FullMD5: "image-md5"},
		{DataType: "17", RecordXML: &model.RecordXML{RecordInfo: model.RecordInfo{DataList: model.DataList{DataItems: []model.DataItem{
			{DataType: "4", FullMD5: "video-md5"},
		}}}}},
	}}}

	service := &Service{}
	assets := service.enrichRecordInfo(record, "")
	if len(assets) != 2 {
		t.Fatalf("asset count = %d, want 2", len(assets))
	}
	if assets[0].Index != "0" || assets[0].ProxyURL != "/image/image-md5" {
		t.Fatalf("unexpected first asset: %#v", assets[0])
	}
	if assets[1].Index != "1.0" || assets[1].ProxyURL != "/video/video-md5" {
		t.Fatalf("unexpected nested asset: %#v", assets[1])
	}
}
