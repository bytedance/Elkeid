package v6

import (
	"strings"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserInfo struct {
	UserName     string   `json:"username" bson:"username"`
	Level        int      `json:"level" bson:"level"`
	SourceIPList []string `json:"source_ip_list" bson:"source_ip_list"`
	IPLimit      bool     `json:"ip_limit" bson:"ip_limit"`
	OtpEnable    bool     `json:"otp_enable" bson:"otp_enable"`
}

// DelUserList 批量删除用户
func DelUserList(c *gin.Context) {
	var userParam = struct {
		UserNameList []string `json:"userNameList"`
	}{}
	err := c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	searchFilter := make(map[string]interface{})
	searchFilter["username"] = common.MongoInside{Inside: userParam.UserNameList}

	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	_, err = userCol.DeleteMany(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, "ok")
}

var roleLevelMap = map[string][]int{"admin": {0}, "advancedUser": {1, 2}, "ordinaryUser": {3}, "advancedOM": {8}, "alarmOM": {6}, "BaselineVulOM": {7}}

func role2Level(roles []string) []int {
	var res []int
	hit := map[string]bool{}
	for _, v := range roles {
		if _, ok := hit[v]; ok {
			continue
		}
		hit[v] = true
		if lvl, ok := roleLevelMap[v]; ok {
			res = append(res, lvl...)
		}
	}
	return res
}

// GetUserList 获取用户列表
//
//	admin:        管理员  0
//	advancedUser: 高级用户（Agent读写权限） 1/2
//	ordinaryUser: 普通用户（Agent只读权限）  3
func GetUserList(c *gin.Context) {

	// 绑定分页数据
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetUserList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定用户筛选数据
	var userRequest = struct {
		UserName string   `json:"username,omitempty"`
		Role     []string `json:"role"`
	}{}
	err = c.BindJSON(&userRequest)
	if err != nil {
		ylog.Errorf("GetUserList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	//判断用户权限，管理员查看全部list，其他用户只能查看自己的list
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	operateUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	var userInfo UserInfo
	err = collection.FindOne(c, bson.M{"username": operateUser}).Decode(&userInfo)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	searchFilter["level"] = common.MongoNinside{Value: []int{4, 5}} //去除hub相关角色
	if userInfo.Level == 0 {
		userNameFilter := bson.A{}
		userNameFilter = append(userNameFilter, bson.M{"username": common.MongoNe{Value: "root"}})
		if userRequest.UserName != "" {
			userNameFilter = append(userNameFilter, bson.M{"username": common.MongoRegex{Regex: userRequest.UserName}})
		}
		searchFilter["$and"] = userNameFilter
	} else {
		if userRequest.UserName == "" || strings.Contains(operateUser.(string), userRequest.UserName) {
			searchFilter["username"] = operateUser
		} else {
			searchFilter["username"] = ""
		}
	}

	userLevelList := role2Level(userRequest.Role)
	if len(userLevelList) != 0 {
		searchFilter["level"] = common.MongoInside{Inside: userLevelList}
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}

	// mongo查询并迭代处理
	var userList []UserInfo
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var userInfo UserInfo
			err := cursor.Decode(&userInfo)
			if err != nil {
				ylog.Errorf("GetUserList", err.Error())
				return err
			}

			userList = append(userList, userInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetUserList", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, userList, *pageResponse)
}
