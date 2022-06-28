package v6

import (
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Module struct {
	ModuleId    primitive.ObjectID `json:"module_id" bson:"_id,omitempty"`
	Name        string             `json:"module_name" binding:"required" bson:"name"`
	PluType     string             `json:"plu_type" bson:"type"`
	Signature   string             `json:"signature" bson:"signature"`
	Version     string             `json:"module_version" bson:"version"`
	SHA256      string             `json:"sha256" bson:"sha256"`
	DownloadURL []string           `json:"download_url" bson:"download_url"`
	Detail      string             `json:"detail" bson:"detail"`
	ModuleType  string             `json:"module_type" bson:"module_type"`
	User        string             `json:"module_user" bson:"user"`
}

// CreateModule 创建一个组件
func CreateModule(c *gin.Context) {
	// 绑定组件信息
	var module Module
	err := c.BindJSON(&module)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// agent名字必须是elkeid-agent
	if module.ModuleType == "agent" {
		if module.Name == "agent" {
			module.Name = "elkeid-agent"
		} else {
			common.CreateResponse(c, common.UnknownErrorCode, "agent's name must be elkeid-agent")
			return
		}
	}

	// 记录创建用户
	createUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	module.User = createUser.(string)

	// 创建组件
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	count, err := collection.CountDocuments(c, bson.M{"name": module.Name, "version": module.Version})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if count > 0 {
		common.CreateResponse(c, common.UnknownErrorCode, "name and version duplicate")
		return
	}

	module.ModuleId = primitive.NewObjectID()
	_, err = collection.InsertOne(c, module)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, nil)
}

// DeleteModule 删除一个组件
func DeleteModule(c *gin.Context) {
	// 绑定组件信息
	var module struct {
		Name    string `json:"module_name" bson:"name"`
		Version string `json:"module_version" bson:"version"`
	}
	err := c.BindJSON(&module)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 判断组件是否存在
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	count, err := collection.CountDocuments(c, bson.M{"name": module.Name, "version": module.Version})
	if count == 0 {
		common.CreateResponse(c, common.UnknownErrorCode, "can't find this module")
		return
	}

	// 删除组件
	_, err = collection.DeleteOne(c, bson.M{"name": module.Name, "version": module.Version})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, nil)

}

// GetModlueInfo 查询一个组件信息
func GetModuleInfo(c *gin.Context) {
	// 绑定组件信息
	var module Module
	err := c.BindJSON(&module)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 判断组件是否存在
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	count, err := collection.CountDocuments(c, bson.M{"name": module.Name, "version": module.Version})
	if count == 0 {
		common.CreateResponse(c, common.UnknownErrorCode, "can't find this module")
		return
	}

	// 查询组件
	err = collection.FindOne(c, bson.M{"name": module.Name, "version": module.Version}).Decode(&module)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, module)
}

// 编辑/更新组件
func UpdateModule(c *gin.Context) {
	// 绑定组件信息
	var module Module
	err := c.BindJSON(&module)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if module.Name == "agent" {
		module.Name = "elkeid-agent"
	}

	// 不允许修改agent name
	if module.ModuleType == "agent" && module.Name != "elkeid-agent" {
		common.CreateResponse(c, common.UnknownErrorCode, "agent's name must be elkeid-agent")
		return
	}

	// 记录编辑用户
	createUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	module.User = createUser.(string)

	// 判断组件是否存在
	var oldModule Module
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	err = collection.FindOne(c, bson.M{"_id": module.ModuleId}).Decode(&oldModule)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, "can't find this module")
		return
	}

	// 判断name version是否不冲突
	searchFilter := make(map[string]interface{})
	searchFilter["name"] = module.Name
	searchFilter["version"] = module.Version
	searchFilter["_id"] = MongoNe{Value: module.ModuleId}
	count, _ := collection.CountDocuments(c, searchFilter)
	if count > 0 {
		common.CreateResponse(c, common.UnknownErrorCode, "name and version duplicate")
		return
	}

	// 更新组件
	_, err = collection.UpdateOne(c, bson.M{"_id": module.ModuleId}, bson.M{"$set": module})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, nil)
}

// 查看组件列表
func GetModuleList(c *gin.Context) {
	type ModuleFilter struct {
		Name       string   `json:"module_name" bson:"name"`
		PluType    []string `json:"plu_type,omitempty" bson:"type"`
		ModuleType []string `json:"module_type,omitempty" bson:"module_type"`
		User       string   `json:"module_user,omitempty" bson:"user"`
	}

	// 绑定分页数据
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetModuleList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定任务筛选数据
	var moduleFilter ModuleFilter
	err = c.BindJSON(&moduleFilter)
	if err != nil {
		ylog.Errorf("GetModuleList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if moduleFilter.Name != "" {
		searchFilter["name"] = MongoRegex{Regex: moduleFilter.Name}
	}
	if len(moduleFilter.PluType) != 0 {
		searchFilter["type"] = MongoInside{Inside: moduleFilter.PluType}
	}
	if len(moduleFilter.ModuleType) != 0 {
		searchFilter["module_type"] = MongoInside{Inside: moduleFilter.ModuleType}
	}
	if moduleFilter.User != "" {
		searchFilter["user"] = moduleFilter.User
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	pageSearch := PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]Module, 0)
	pageResponse, err := DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var module Module
			err := cursor.Decode(&module)
			if err != nil {
				ylog.Errorf("GetMoudleList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, module)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 获取组件ID
func GetModuleId(c *gin.Context) {
	// 绑定组件信息
	var module Module
	err := c.BindJSON(&module)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	if module.Name == "agent" {
		module.Name = "elkeid-agent"
	}

	// 获取组件ID
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	err = collection.FindOne(c, bson.M{"name": module.Name, "version": module.Version}).Decode(&module)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, "can't find this module")
		return
	}

	// 返回组件ID
	common.CreateResponse(c, common.SuccessCode, module.ModuleId)
	return
}
