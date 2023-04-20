package v6

import (
	"strings"

	"github.com/bytedance/Elkeid/server/manager/internal/alarm_whitelist"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// ############################### Data Struct ###############################
type WhiteListDelReq struct {
	IdList []string `json:"id_list"`
}

type WhiteListDelRspItem struct {
	ID   string `json:"id" bson:"id"`
	Code int    `json:"code" bson:"code"`
	Msg  string `json:"msg" bson:"msg"`
}

type WhiteListUpdateReq struct {
	ID       string `json:"id" bson:"id"`
	RuleName string `json:"white_rule_name" bson:"white_rule_name"`
	RuleDesc string `json:"white_rule_desc" bson:"white_rule_desc"`
}

// ############################### Function ###############################
func GetWhiteListWithCombine(c *gin.Context, whitelistType string) {
	var pageRequest common.PageRequest
	var assetKeyList = []string{alarm_whitelist.WhitelistKeyAgentID, alarm_whitelist.WhitelistKeyClusterID}
	var contentFilterKeyList = make([]string, 0, 10)
	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	ruleNameKey := alarm_whitelist.GetWhiteListRuleNameFieldName(whitelistType)

	var filter alarm_whitelist.WhiteListDataQueryFilter
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
		var keyList []string
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

	if filter.MatchContent != nil {
		contentFilterKeyList = append(contentFilterKeyList, assetKeyList...)
		contentFilterKeyList = append(contentFilterKeyList, ruleNameKey)
		contRule := common.FilterContent{
			Key:       "filter",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$elemMatch",
					Value: bson.M{
						"key":         bson.M{"$nin": contentFilterKeyList},
						"rules.value": bson.M{"$regex": *filter.MatchContent}},
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, contRule)
	}

	if filter.MatchAlarmName != nil {
		contRule := common.FilterContent{
			Key:       "filter",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$elemMatch",
					Value: bson.M{
						"key":         bson.M{"$eq": ruleNameKey},
						"rules.value": bson.M{"$regex": *filter.MatchAlarmName}},
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, contRule)
	}

	if filter.WhiteRuleName != nil {
		descRule := common.FilterContent{
			Key:       "name",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$regex",
					Value:    *filter.WhiteRuleName,
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, descRule)
	}

	if filter.WhiteRuleDesc != nil {
		whiteRule := common.FilterContent{
			Key:       "desc",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$regex",
					Value:    *filter.WhiteRuleDesc,
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, whiteRule)
	}

	if filter.InsertTimeStart > 0 {
		timeStart := common.FilterContent{
			Key:       "insert_time",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$gte",
					Value:    filter.InsertTimeStart,
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, timeStart)
	}

	if filter.InsertTimeEnd > 0 {
		timeEnd := common.FilterContent{
			Key:       "insert_time",
			Condition: "$and",
			Rules: []common.FilterRule{
				{
					Operator: "$lte",
					Value:    filter.InsertTimeEnd,
				},
			},
		}
		searchFilter.Filter = append(searchFilter.Filter, timeEnd)
	}

	if filter.RangeType != nil {
		if *filter.RangeType == 0 {
			rgaRule := common.FilterContent{
				Key:       "filter.key",
				Condition: "$and",
				Rules: []common.FilterRule{
					{
						Operator: "$nin",
						Value:    assetKeyList,
					},
				},
			}
			searchFilter.Filter = append(searchFilter.Filter, rgaRule)
		} else if *filter.RangeType == 1 {
			rgsRule := common.FilterContent{
				Key:       "filter.key",
				Condition: "$and",
				Rules: []common.FilterRule{
					{
						Operator: "$in",
						Value:    assetKeyList,
					},
				},
			}
			searchFilter.Filter = append(searchFilter.Filter, rgsRule)
		}
	}

	collection, err := alarm_whitelist.QueryWhitelistMongodbCollection(whitelistType)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	pageOption := common.PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   searchFilter.Transform(),
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageOption.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default order
		pageOption.Sorter = bson.M{"update_time": -1}
	}
	var saveWhiteList []alarm_whitelist.WhiteListDataWithCombineCondition
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageOption,
		func(cursor *mongo.Cursor) error {
			var item alarm_whitelist.WhiteListDbData
			var rangeType = alarm_whitelist.WhitelistRangeTypeAll
			var rangeValue = ""
			matchCond := make([]alarm_whitelist.WhiteListContent, 0, 5)
			var matchKey = ""
			var matchType = alarm_whitelist.WhitelistMatchKeyUnkownIndex
			var matchCont = ""
			var matchName = ""
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("QueryWhiteLists", err.Error())
				return err
			}

			for _, i := range item.Filter {
				if len(i.Rules) == 0 {
					continue
				}

				tmpMatchKey := i.Key
				matchTypeStr := i.Rules[0].Operator
				tmpMatchCont := i.Rules[0].Value.(string)

				if tmpMatchKey == ruleNameKey {
					// set the name
					matchName = tmpMatchCont
					continue
				}

				if tmpMatchKey == alarm_whitelist.WhitelistKeyAgentID {
					rangeType = alarm_whitelist.WhitelistRangeTypeSingle
					// query host name
					var hInfo AlarmDetailDataBaseAgent
					_ = GetAgentDetail(c, tmpMatchCont, &hInfo)
					// rangeValue = tmpMatchCont
					rangeValue = hInfo.HostName
					continue
				}

				if tmpMatchKey == alarm_whitelist.WhitelistKeyClusterID {
					rangeType = alarm_whitelist.WhitelistRangeTypeSingle
					// query cluster name
					cInfo := KubeQueryClusterInfo(c, tmpMatchCont)
					// rangeValue = tmpMatchCont
					rangeValue = cInfo.ClusterName
					continue
				}

				matchCont = tmpMatchCont
				matchKey = strings.TrimPrefix(tmpMatchKey, alarm_whitelist.WhitelistKeyKcPrefix)

				switch matchTypeStr {
				case alarm_whitelist.WhitelistMatchKeyEqValue:
					matchType = alarm_whitelist.WhitelistMatchKeyEqIndex
				case alarm_whitelist.WhitelistMatchKeyRegexValue:
					matchType = alarm_whitelist.WhitelistMatchKeyRegexIndex
				default:
					matchType = alarm_whitelist.WhitelistMatchKeyUnkownIndex
				}

				matchCond = append(matchCond, alarm_whitelist.WhiteListContent{
					MatchKey:     matchKey,
					MatchType:    matchType,
					MatchContent: matchCont,
				})
			}

			var tmpData = alarm_whitelist.WhiteListDataWithCombineCondition{
				Id:             item.Id,
				RangeType:      rangeType,
				RangeIndex:     rangeValue,
				MatchAlarmName: matchName,
				MatchCombine:   matchCond,
				UpdateTime:     item.InsertTime,
				WhiteRuleName:  item.Name,
				WhiteRuleDesc:  item.Desc,
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

func WhiteListDelMulti(c *gin.Context, whitelistType string) {
	req := WhiteListDelReq{}
	res := make([]WhiteListDelRspItem, 0, len(req.IdList))
	err := c.BindJSON(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = alarm_whitelist.WhiteListDelMulti(c, whitelistType, req.IdList)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, res)
}

func WhiteListAddMultiWithCombine(c *gin.Context, whitelistType string) {
	var req alarm_whitelist.WhiteListAddReq
	err := c.BindJSON(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = alarm_whitelist.WhiteListAddMultiWithCombine(c, whitelistType, &req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, "ok")
}

func WhiteListUpdateOne(c *gin.Context, whitelistType string) {
	var req WhiteListUpdateReq
	err := c.BindJSON(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = alarm_whitelist.UpdateWhitelistNameAndDesc(c, whitelistType, req.ID, req.RuleName, req.RuleDesc)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, "ok")
}
