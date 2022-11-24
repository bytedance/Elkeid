package alarm_whitelist

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type WhiteListAddReq struct {
	RangeType      int                `json:"range_type" bson:"range_type"`
	RangeIndex     string             `json:"range_index" bson:"range_index"`
	Filter         []WhiteListContent `json:"filter" bson:"filter"`
	Name           string             `json:"name" bson:"name"`
	AlertType      string             `json:"alert_type" bson:"alert_type"`
	RangeIndexType *string            `json:"range_index_type,omitempty" bson:"range_index_type,omitempty"`
	WhiteRuleName  *string            `json:"white_rule_name,omitempty" bson:"white_rule_name,omitempty"`
	WhiteRuleDesc  *string            `json:"white_rule_desc,omitempty" bson:"white_rule_desc,omitempty"`
}

func sendInotifyToWitelistWorker(whitelistType string, msg *WLUpdater) {
	switch whitelistType {
	case WhitelistTypeHids:
		WLWorker.Add(msg)
	case WhitelistTypeRasp:
		RaspWLWorker.Add(msg)
	case WhitelistTypeKube:
		KubeWLWorker.Add(msg)
	case WhitelistTypeVirus:
		VirusWLWorker.Add(msg)
	default:
		return
	}
}

func UpdateWhitelistNameAndDesc(ctx context.Context, whitelistType string, whitelistID string, name string, desc string) error {
	objId, err := primitive.ObjectIDFromHex(whitelistID)
	if err != nil {
		return err
	}

	col, err := QueryWhitelistMongodbCollection(whitelistType)
	upOpt := bson.M{
		"update_time": time.Now().Unix(),
	}

	if name != "" {
		upOpt["name"] = name
	}

	if desc != "" {
		upOpt["desc"] = desc
	}

	// update the rule
	_, err = col.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": upOpt})
	if err != nil {
		return err
	}

	return nil
}

func WhiteListAddMultiWithCombine(ctx context.Context, whitelistType string, data *WhiteListAddReq) error {
	var nowUnixTime int64 = 0
	var assetId = ""
	var assetKey = ""
	var ruleName = ""
	var keyPrefix = ""
	var whiteRuleName = ""
	var whiteRuleDesc = ""

	ruleNameKey := GetWhiteListRuleNameFieldName(whitelistType)

	if data.RangeType == WhitelistRangeTypeSingle {
		// must set agent_id
		if data.RangeIndex == "" {
			return errors.New("empty asset id for single range")
		}

		assetId = data.RangeIndex
		if data.RangeIndexType != nil {
			switch *data.RangeIndexType {
			case WhitelistRangeIndexTypeCluster:
				assetKey = WhitelistKeyClusterID
				break
			default:
				assetKey = WhitelistKeyAgentID
				break
			}
		} else {
			// default is agent_id
			assetKey = WhitelistKeyAgentID
		}
	}

	if len(data.Filter) == 0 {
		// nothing to do
		return nil
	}

	if data.Name == "" {
		return errors.New("empty data type")
	} else {
		ruleName = data.Name
	}

	if data.AlertType != "" {
		// check for killchain
		if data.AlertType == "killchain" {
			keyPrefix = WhitelistKeyKcPrefix
		}
	}

	if data.WhiteRuleName != nil {
		whiteRuleName = *data.WhiteRuleName
	} else {
		return errors.New("empty white rule name")
	}

	if data.WhiteRuleDesc != nil {
		whiteRuleDesc = *data.WhiteRuleDesc
	}

	nowUnixTime = time.Now().Unix()

	item := WhitelistDbDataContent{
		Type:       0,
		Filter:     make([]common.FilterContent, 0),
		Condition:  "$and",
		InsertTime: nowUnixTime,
		UpdateTime: nowUnixTime,
		Name:       whiteRuleName,
		Desc:       whiteRuleDesc,
	}

	// filter range
	if assetId != "" {
		rangeFilter := common.FilterContent{
			Key:       assetKey,
			Condition: "$and",
			Rules: []common.FilterRule{
				{Value: assetId, Operator: "$eq"},
			},
		}
		item.Filter = append(item.Filter, rangeFilter)
	}

	// filter data_type
	if ruleName != "" {
		rangeFilter := common.FilterContent{
			Key:       ruleNameKey,
			Condition: "$and",
			Rules: []common.FilterRule{
				{Value: ruleName, Operator: "$eq"},
			},
		}
		item.Filter = append(item.Filter, rangeFilter)
	}

	for _, k := range data.Filter {

		// filter argv
		if k.MatchContent == "" {
			ylog.Errorf("WhiteListAddMulti", "Receiv empty match content")
			continue
		}

		y, yOk := WhitelistKeyDbFieldMap[k.MatchKey]
		if !yOk {
			ylog.Errorf("WhiteListAddMulti", "Receive unknown match key %s", k.MatchKey)
			continue
		}
		fy := fmt.Sprintf("%s%s", keyPrefix, y)
		if (keyPrefix == WhitelistKeyKcPrefix) && (y == "top_chain") {
			fy = y
		}

		t, tOk := WhitelistMatchTypeMap[k.MatchType]
		if !tOk {
			ylog.Errorf("WhiteListAddMulti", "Receive unknown match type %d", k.MatchType)
			continue
		}

		matchFilter := common.FilterContent{
			Key:       fy,
			Condition: "$and",
			Rules: []common.FilterRule{
				{Value: k.MatchContent, Operator: t},
			},
		}

		item.Filter = append(item.Filter, matchFilter)
	}

	col, err := QueryWhitelistMongodbCollection(whitelistType)
	if err != nil {
		return err
	}

	iRes, err := col.InsertOne(ctx, item)
	if err != nil {
		return err
	}

	filter := common.FilterQuery{Filter: item.Filter, Condition: item.Condition}
	tmp := &WLUpdater{
		Filter:  filter.Transform(),
		Updater: bson.M{"$set": bson.M{"__hit_wl": true, "__update_time": nowUnixTime}, "$addToSet": bson.M{"__wl": iRes.InsertedID}},
	}
	// v1.InotifyWhiteWorker(tmp)
	sendInotifyToWitelistWorker(whitelistType, tmp)

	return nil
}

func WhiteListDelMulti(ctx context.Context, whitelistType string, idList []string) error {
	col, err := QueryWhitelistMongodbCollection(whitelistType)
	if err != nil {
		return err
	}

	objIDList := make([]primitive.ObjectID, 0, len(idList))
	for _, v := range idList {
		objID, err := primitive.ObjectIDFromHex(v)
		if err != nil {
			continue
		}
		objIDList = append(objIDList, objID)
	}

	_, err = col.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": objIDList}})
	if err != nil {
		return err
	}

	for _, v := range objIDList {
		tmp1 := &WLUpdater{
			Filter:  bson.M{"__wl": bson.M{"$size": 1}, "__wl.0": v},
			Updater: bson.M{"$set": bson.M{"__hit_wl": false, "__update_time": time.Now().Unix()}},
		}
		// v1.InotifyWhiteWorker(tmp1)
		sendInotifyToWitelistWorker(whitelistType, tmp1)

		tmp2 := &WLUpdater{
			Filter:  bson.M{},
			Updater: bson.M{"$pull": bson.M{"__wl": v}},
		}
		// v1.InotifyWhiteWorker(tmp2)
		sendInotifyToWitelistWorker(whitelistType, tmp2)
	}

	return nil
}
