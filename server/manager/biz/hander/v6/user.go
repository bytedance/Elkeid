package v6

import (
	"fmt"
	"strings"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserInfo struct {
	UserName string `json:"username"`
	Level    int    `json:"level"`
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
	searchFilter["username"] = MongoInside{Inside: userParam.UserNameList}

	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	_, err = userCol.DeleteMany(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// GetUserList 获取用户列表
func GetUserList(c *gin.Context) {

	// 绑定分页数据
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetUserList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定用户筛选数据
	var userRequest = struct {
		UserName  string   `json:"username,omitempty"`
		Role      []string `json:"role"`
		Authority []string `json:"authority"`
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
	if userInfo.Level == 0 {
		if userRequest.UserName != "" {
			searchFilter["username"] = MongoRegex{Regex: userRequest.UserName}
		}
	} else {
		if userRequest.UserName == "" || strings.Contains(operateUser.(string), userRequest.UserName) {
			searchFilter["username"] = operateUser
		} else {
			searchFilter["username"] = ""
		}
	}

	// 生成用户权限筛选列表
	var (
		ifAdmin     bool = false
		ifUser      bool = false
		ifRead      bool = false
		ifReadWrite bool = false
	)
	if len(userRequest.Role) == 0 {
		ifAdmin = true
		ifUser = true
	} else {
		for _, role := range userRequest.Role {
			if role == "admin" {
				ifAdmin = true
			} else if role == "user" {
				ifUser = true
			}
		}
	}
	if len(userRequest.Authority) == 0 {
		ifRead = true
		ifReadWrite = true
	} else {
		for _, role := range userRequest.Authority {
			if role == "read" {
				ifRead = true
			} else if role == "read_write" {
				ifReadWrite = true
			}
		}
	}
	var userLevelList []int
	if ifUser {
		if ifReadWrite {
			userLevelList = append(userLevelList, 2)
		}
		if ifRead {
			userLevelList = append(userLevelList, 3)
		}
	}
	if ifAdmin {
		if ifReadWrite {
			userLevelList = append(userLevelList, 0)
		}
		if ifRead && len(userLevelList) == 0 {
			userLevelList = append(userLevelList, -1)
		}
	}

	if len(userLevelList) != 0 {
		searchFilter["level"] = MongoInside{Inside: userLevelList}
	}

	// 拼接分页数据
	pageSearch := PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}

	fmt.Println("\n\n\n")
	fmt.Println(searchFilter)

	// mongo查询并迭代处理
	var userList []UserInfo
	pageResponse, err := DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var userInfo UserInfo
			err := cursor.Decode(&userInfo)
			if err != nil {
				ylog.Errorf("GetUserList", err.Error())
				return err
			}
			if strings.Contains(userInfo.UserName, "test") {
				fmt.Println(userInfo.UserName)
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
