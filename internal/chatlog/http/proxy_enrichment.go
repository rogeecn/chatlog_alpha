package http

import (
	"strconv"
	"strings"

	"github.com/sjzar/chatlog/internal/model"
)

func (s *Service) enrichMessages(messages []*model.Message) {
	for _, message := range messages {
		if message == nil {
			continue
		}
		message.RefreshProxyFields()
		if message.Contents == nil {
			continue
		}
		recordInfo, ok := message.Contents["recordInfo"].(*model.RecordInfo)
		if !ok || recordInfo == nil {
			continue
		}
		assets := s.enrichRecordInfo(recordInfo, "")
		if len(assets) > 0 {
			message.Contents["assets"] = assets
		}
	}
}

func (s *Service) enrichRecordInfo(recordInfo *model.RecordInfo, prefix string) []model.RecordAsset {
	if recordInfo == nil {
		return nil
	}
	assets := make([]model.RecordAsset, 0, len(recordInfo.DataList.DataItems))
	for index := range recordInfo.DataList.DataItems {
		item := &recordInfo.DataList.DataItems[index]
		assetIndex := strconv.Itoa(index)
		if prefix != "" {
			assetIndex = prefix + "." + assetIndex
		}
		s.enrichRecordDataItem(item)
		if item.DataType == "17" && item.RecordXML != nil {
			nested := s.enrichRecordInfo(&item.RecordXML.RecordInfo, assetIndex)
			item.RecordXML.RecordInfo.Assets = nested
			assets = append(assets, nested...)
			continue
		}
		assets = append(assets, item.ToAsset(assetIndex))
	}
	recordInfo.Assets = assets
	return assets
}

func (s *Service) enrichRecordDataItem(item *model.DataItem) {
	if item == nil {
		return
	}
	switch item.DataType {
	case "2":
		setRecordItemMD5Proxy(item, "image")
	case "4":
		setRecordItemMD5Proxy(item, "video")
	case "8":
		if strings.TrimSpace(item.FullMD5) != "" {
			item.SetResolvedProxy("file", strings.TrimSpace(item.FullMD5), "fullmd5")
			return
		}
		name := strings.TrimSpace(item.DataTitle)
		if name == "" {
			item.SetUnresolvedProxy("file", "missing_fullmd5")
			return
		}
		media, err := s.db.GetMediaByName("file", name, item.DataSizeInt64())
		if err == nil && media != nil && strings.TrimSpace(media.Key) != "" {
			source := "hardlink_by_name"
			if item.DataSizeInt64() > 0 {
				source = "hardlink_by_name_size"
			}
			item.SetResolvedProxy("file", media.Key, source)
			return
		}
		item.SetUnresolvedProxy("file", "missing_fullmd5")
	case "3":
		item.SetUnresolvedProxy("voice", "record_voice_unresolved")
	}
}

func setRecordItemMD5Proxy(item *model.DataItem, mediaType string) {
	if key := strings.TrimSpace(item.FullMD5); key != "" {
		item.SetResolvedProxy(mediaType, key, "fullmd5")
		return
	}
	item.SetUnresolvedProxy(mediaType, "missing_fullmd5")
}
