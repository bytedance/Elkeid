package alarm_whitelist

import (
	"errors"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"go.mongodb.org/mongo-driver/mongo"
)

// ############################### Data Struct ###############################
type AlarmDbDataForWhite struct {
	Id      string `json:"_id" bson:"_id"`
	AgentId string `json:"agent_id" bson:"agent_id"`
	Status  int    `json:"__alarm_status" bson:"__alarm_status"`
	HitWl   bool   `json:"__hit_wl" bson:"__hit_wl"`
}

type WhiteListDataQueryFilter struct {
	MatchKey        []string `json:"match_key"`
	MatchContent    *string  `json:"content,omitempty"`
	RangeType       *int     `json:"range_type,omitempty"`
	InsertTimeStart int64    `json:"update_time_start"`
	InsertTimeEnd   int64    `json:"update_time_end"`
	MatchAlarmName  *string  `json:"match_alarm_name,omitempty"`
	WhiteRuleName   *string  `json:"white_rule_name,omitempty"`
	WhiteRuleDesc   *string  `json:"white_rule_desc,omitempty"`
}

type WhiteListDbData struct {
	Id         string                 `json:"_id" bson:"_id"`
	Type       int                    `json:"type" bson:"type"`
	Filter     []common.FilterContent `json:"filter" binding:"dive" bson:"filter"`
	Condition  string                 `json:"condition" binding:"oneof=$and $or $nor" bson:"condition"`
	InsertTime int64                  `json:"insert_time" bson:"insert_time"`
	UpdateTime int64                  `json:"update_time" bson:"update_time"`
	Name       string                 `json:"name,omitempty" bson:"name,omitempty"`
	Desc       string                 `json:"desc,omitempty" bson:"desc,omitempty"`
}

type WhiteListData struct {
	Id             string `json:"id" bson:"id"`
	RangeType      int    `json:"range_type" bson:"range_type"`
	RangeIndex     string `json:"range_index" bson:"range_index"`
	MatchKey       string `json:"match_key" bson:"match_key"`
	MatchType      int    `json:"match_type" bson:"match_type"`
	MatchContent   string `json:"match_content" bson:"match_content"`
	MatchAlarmName string `json:"match_alarm_name" bson:"match_alarm_name"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
}

type WhiteListContent struct {
	MatchKey     string `json:"match_key" bson:"match_key"`
	MatchType    int    `json:"match_type" bson:"match_type"`
	MatchContent string `json:"match_content" bson:"match_content"`
}

type WhiteListDataWithCombineCondition struct {
	Id             string             `json:"id" bson:"id"`
	RangeType      int                `json:"range_type" bson:"range_type"`
	RangeIndex     string             `json:"range_index" bson:"range_index"`
	MatchAlarmName string             `json:"match_alarm_name" bson:"match_alarm_name"`
	MatchCombine   []WhiteListContent `json:"match_combine" bson:"match_combine"`
	UpdateTime     int64              `json:"update_time" bson:"update_time"`
	WhiteRuleName  string             `json:"white_rule_name" bson:"white_rule_name"`
	WhiteRuleDesc  string             `json:"white_rule_desc,omitempty" bson:"white_rule_desc,omitempty"`
}

type WhitelistDbDataContent struct {
	Type       int                    `json:"type" bson:"type"`
	Filter     []common.FilterContent `json:"filter" binding:"dive" bson:"filter"`
	Condition  string                 `json:"condition" binding:"oneof=$and $or $nor" bson:"condition"`
	InsertTime int64                  `json:"insert_time" bson:"insert_time"`
	UpdateTime int64                  `json:"update_time" bson:"update_time"`
	Name       string                 `json:"name,omitempty" bson:"name,omitempty"`
	Desc       string                 `json:"desc,omitempty" bson:"desc,omitempty"`
}

// ############################### Function ###############################
func getWhiteCollectName(whitelistType string) (string, error) {
	retName := ""

	switch whitelistType {
	case WhitelistTypeHids:
		retName = infra.HubWhiteListCollectionV1
	case WhitelistTypeRasp:
		retName = infra.RaspAlarmWhiteV1
	case WhitelistTypeKube:
		retName = infra.KubeAlarmWhiteCollectionV1
	case WhitelistTypeVirus:
		retName = infra.VirusDetectionWhiteCollectionV1
	default:
		typeErr := errors.New("Unkown whitelist type")
		return retName, typeErr
	}

	return retName, nil
}

func GetWhiteListRuleNameFieldName(white_type string) string {
	var retStr = ""

	switch white_type {
	case WhitelistTypeRasp:
		retStr = WhitelistKeyRaspName
	// case WhitelistTypeKube:
	default:
		retStr = WhitelistKeyName
	}

	return retStr
}

func QueryWhitelistMongodbCollection(alarmType string) (*mongo.Collection, error) {
	colName, err := getWhiteCollectName(alarmType)
	if err != nil {
		return nil, err
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(colName)

	return col, nil
}
