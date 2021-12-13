package v6

import (
	"errors"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	v1 "github.com/bytedance/Elkeid/server/manager/biz/hander/v1"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// ############################### Data Struct ###############################
type WhiteListDataQueryFilter struct {
	MatchKey     []string `json:"match_key"`
	MatchContent string   `json:"content"`
}

type WhiteListDbData struct {
	Id         string                 `json:"_id" bson:"_id"`
	Type       int                    `json:"type" bson:"type"`
	Filter     []common.FilterContent `json:"filter" binding:"dive" bson:"filter"`
	Condition  string                 `json:"condition" binding:"oneof=$and $or $nor" bson:"condition"`
	InsertTime int64                  `json:"insert_time" bson:"insert_time"`
	UpdateTime int64                  `json:"update_time" bson:"update_time"`
}

type WhiteListData struct {
	Id           string `json:"id" bson:"id"`
	RangeType    int    `json:"range_type" bson:"range_type"`
	RangeIndex   string `json:"range_index" bson:"range_index"`
	MatchKey     string `json:"match_key" bson:"match_key"`
	MatchType    int    `json:"match_type" bson:"match_type"`
	MatchContent string `json:"match_content" bson:"match_content"`
	UpdateTime   int64  `json:"update_time" bson:"update_time"`
}

type WhiteListContent struct {
	MatchKey     string `json:"match_key" bson:"match_key"`
	MatchType    int    `json:"match_type" bson:"match_type"`
	MatchContent string `json:"match_content" bson:"match_content"`
}

type WhiteListAddReq struct {
	RangeType  int                `json:"range_type" bson:"range_type"`
	RangeIndex string             `json:"range_index" bson:"range_index"`
	Filter     []WhiteListContent `json:"filter" bson:"filter"`
}

type WhiteListDelReq struct {
	IdList []string `json:"id_list"`
}

type WhiteListDelRsp struct {
	ID   string `json:"id" bson:"id"`
	Code int    `json:"code" bson:"code"`
	Msg  string `json:"msg" bson:"msg"`
}

// ############################### Variable ###############################
const (
	WHITELIST_RANGE_TYPE_ALL    int = 0
	WHITELIST_RANGE_TYPE_SINGLE int = 1
)

const (
	WHITELIST_MATCH_KEY_UNKOWN_INDEX int    = -1
	WHITELIST_MATCH_KEY_EQ_INDEX     int    = 0
	WHITELIST_MATCH_KEY_EQ_VALUE     string = "$eq"
	WHITELIST_MATCH_KEY_REGEX_INDEX  int    = 1
	WHITELIST_MATCH_KEY_REGEX_VALUE  string = "$regex"
)

const (
	WHITELIST_KEY_AGENT_ID string = "agent_id"
)

var WHITELIST_MATCH_TYPE map[int]string = map[int]string{
	WHITELIST_MATCH_KEY_EQ_INDEX:    "$eq",
	WHITELIST_MATCH_KEY_REGEX_INDEX: "$regex",
}

var WHITELIST_KEY_TYPE map[string]string = map[string]string{
	"argv":        "argv",
	"pgid_argv":   "pgid_argv",
	"exe":         "exe",
	"sip":         "sip",
	"dip":         "dip",
	"pid_tree":    "pid_tree",
	"ld_preload":  "ld_preload",
	"ko_file":     "ko_file",
	"module_name": "module_name",
}

// ############################### Function ###############################
func GetWhiteList(c *gin.Context) {
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	var filter WhiteListDataQueryFilter
	err = c.BindJSON(&filter)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	searchFilter := common.FilterQuery{
		Filter:    make([]common.FilterContent, 0),
		Condition: "$and",
	}

	if len(filter.MatchKey) > 0 {
		keyList := []string{}
		for _, m := range filter.MatchKey {
			if len(m) == 0 {
				continue
			}
			keyList = append(keyList, m)
		}

		matchRule := common.FilterContent{
			Key:       "filter.key",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$in",
					Value:    keyList,
				},
			},
		}

		searchFilter.Filter = append(searchFilter.Filter, matchRule)
	}

	if filter.MatchContent != "" {
		/*
			contRule := common.FilterContent{
				Key:       "filter.rules.value",
				Condition: "$and",
				Rules: []common.FilterRule{
					{
						Operator: "$regex",
						Value:    filter.MatchContent,
					},
				},
			}*/
		contRule := common.FilterContent{
			Key:       "filter",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$elemMatch",
					Value:    bson.M{"key": bson.M{"$ne": "agent_id"}, "rules.value": bson.M{"$regex": filter.MatchContent}},
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, contRule)
	}

	ylog.Infof("Whitelist filter", "%+v", searchFilter.Transform())

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
	pageOption := PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   searchFilter.Transform(),
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageOption.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default order
		pageOption.Sorter = bson.M{"update_time": -1}
	}
	var saveWhiteList []WhiteListData = []WhiteListData{}
	pageResponse, err := DBSearchPaginate(
		collection,
		pageOption,
		func(cursor *mongo.Cursor) error {
			var item WhiteListDbData
			var rangeType int = WHITELIST_RANGE_TYPE_ALL
			var rangeValue string = ""
			var matchKey string = ""
			var matchType int = WHITELIST_MATCH_KEY_UNKOWN_INDEX
			var matchCont string = ""
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("QueryWhiteLists", err.Error())
				return err
			}

			for _, i := range item.Filter {
				if len(i.Rules) == 0 {
					continue
				}

				if i.Key == WHITELIST_KEY_AGENT_ID {
					rangeType = WHITELIST_RANGE_TYPE_SINGLE
					rangeValue = i.Rules[0].Value.(string)
					continue
				}

				matchKey = i.Key
				matchTypeStr := i.Rules[0].Operator
				matchCont = i.Rules[0].Value.(string)
				switch matchTypeStr {
				case WHITELIST_MATCH_KEY_EQ_VALUE:
					matchType = WHITELIST_MATCH_KEY_EQ_INDEX
				case WHITELIST_MATCH_KEY_REGEX_VALUE:
					matchType = WHITELIST_MATCH_KEY_REGEX_INDEX
				default:
					matchType = WHITELIST_MATCH_KEY_UNKOWN_INDEX
				}
			}

			var tmpData WhiteListData = WhiteListData{
				Id:           item.Id,
				RangeType:    rangeType,
				RangeIndex:   rangeValue,
				MatchKey:     matchKey,
				MatchType:    matchType,
				MatchContent: matchCont,
				UpdateTime:   item.UpdateTime,
			}
			saveWhiteList = append(saveWhiteList, tmpData)
			return nil
		})

	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, saveWhiteList, *pageResponse)
}

func WhiteListAddMulti(c *gin.Context) {
	var req WhiteListAddReq
	var nowUnixTime int64 = 0
	var agentId string = ""
	err := c.BindJSON(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	if req.RangeType == WHITELIST_RANGE_TYPE_SINGLE {
		// must set agent_id
		if req.RangeIndex == "" {
			err = errors.New("empty agent id for single host range")
			CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}

		agentId = req.RangeIndex
	}

	if len(req.Filter) == 0 {
		// nothing to do
		goto WLADDSUCC
	}

	nowUnixTime = time.Now().Unix()
	for _, k := range req.Filter {
		item := v1.WhiteList{
			Type:       0,
			Filter:     make([]common.FilterContent, 0),
			Condition:  "$and",
			InsertTime: nowUnixTime,
			UpdateTime: nowUnixTime,
		}

		// filter argv
		if k.MatchContent == "" {
			ylog.Errorf("WhiteListAddMulti", "Receiv empty match content")
			continue
		}

		y, yOk := WHITELIST_KEY_TYPE[k.MatchKey]
		if !yOk {
			ylog.Errorf("WhiteListAddMulti", "Receiv unkown match key %d", k.MatchKey)
			continue
		}

		t, tOk := WHITELIST_MATCH_TYPE[k.MatchType]
		if !tOk {
			ylog.Errorf("WhiteListAddMulti", "Receiv unkown match type %d", k.MatchType)
			continue
		}

		matchFilter := common.FilterContent{
			Key:       y,
			Condition: "$and",
			Rules: []common.FilterRule{
				{Value: k.MatchContent, Operator: t},
			},
		}

		item.Filter = append(item.Filter, matchFilter)

		// filter range
		if agentId != "" {
			rangeFilter := common.FilterContent{
				Key:       WHITELIST_KEY_AGENT_ID,
				Condition: "$and",
				Rules: []common.FilterRule{
					{Value: agentId, Operator: "$eq"},
				},
			}
			item.Filter = append(item.Filter, rangeFilter)
		}

		col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
		iRes, err := col.InsertOne(c, item)
		if err != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		filter := common.FilterQuery{Filter: item.Filter, Condition: item.Condition}
		tmp := &v1.WLUpdater{
			Filter:  filter.Transform(),
			Updater: bson.M{"$set": bson.M{"__hit_wl": true, "__update_time": nowUnixTime}, "$addToSet": bson.M{"__wl": iRes.InsertedID}},
		}
		v1.InotifyWhiteWorker(tmp)
	}
WLADDSUCC:
	CreateResponse(c, common.SuccessCode, "ok")
}

func WhiteListDelMulti(c *gin.Context) {
	req := WhiteListDelReq{}
	err := c.BindJSON(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	res := make([]WhiteListDelRsp, 0, len(req.IdList))
	objList := make([]primitive.ObjectID, len(req.IdList))
	for _, v := range req.IdList {
		tmp := WhiteListDelRsp{
			ID:   v,
			Code: 0,
			Msg:  "ok",
		}

		objId, err := primitive.ObjectIDFromHex(v)
		if err != nil {
			tmp.Code = 1
			tmp.Msg = err.Error()
		} else {
			objList = append(objList, objId)
		}
		res = append(res, tmp)
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
	_, err = col.DeleteMany(c, bson.M{"_id": bson.M{"$in": objList}})
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	for _, v := range objList {
		tmp1 := &v1.WLUpdater{
			Filter:  bson.M{"__wl": bson.M{"$size": 1}, "__wl.0": v},
			Updater: bson.M{"$set": bson.M{"__hit_wl": false, "__update_time": time.Now().Unix()}},
		}
		v1.InotifyWhiteWorker(tmp1)

		tmp2 := &v1.WLUpdater{
			Filter:  bson.M{},
			Updater: bson.M{"$pull": bson.M{"__wl": v}},
		}
		v1.InotifyWhiteWorker(tmp2)
	}

	CreateResponse(c, common.SuccessCode, res)
}
