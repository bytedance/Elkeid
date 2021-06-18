package v1

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

//GetConfigByID return agent config by agent_id.
func GetConfigByID(c *gin.Context) {
	agentID := c.Param("id")
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	var hb AgentHBInfo
	filter := bson.M{"agent_id": agentID}
	err := collection.FindOne(context.Background(), filter).Decode(&hb)
	if err != nil && err != mongo.ErrNoDocuments {
		ylog.Errorf("GetConfigByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	if hb.Config == nil || len(hb.Config) == 0 {
		//Read the default version
		defaultConfig := getDefaultConfig()
		if defaultConfig == nil {
			common.CreateResponse(c, common.SuccessCode, []AgentConfigMsg{})
			return
		}
		common.CreateResponse(c, common.SuccessCode, defaultConfig)
		return
	}

	common.CreateResponse(c, common.SuccessCode, hb.Config)
	return
}

//GetDefaultConfig get default agent config
func GetDefaultConfig(c *gin.Context) {
	defaultConfig := getDefaultConfig()
	if defaultConfig == nil {
		common.CreateResponse(c, common.DBOperateErrorCode, "load default config error")
		return
	}
	common.CreateResponse(c, common.SuccessCode, defaultConfig)
	return
}

func getDefaultConfig() []AgentConfigMsg {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.DefaultCollection)
	var config DefaultConfig
	filter := bson.M{"type": DefaultAgentConfig, "version": DefaultConfigVersion}
	err := collection.FindOne(context.Background(), filter).Decode(&config)
	if err != nil && err != mongo.ErrNoDocuments {
		ylog.Errorf("GetDefaultConfig", err.Error())
		return nil
	}
	return config.Config
}

//UpdateDefaultConfig update default agent config
func UpdateDefaultConfig(c *gin.Context) {
	var defaultConfigModel DefaultConfig

	err := c.BindJSON(&defaultConfigModel)
	if err != nil {
		ylog.Errorf("UpdateDefaultConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	defaultConfigModel.UpdateTime = time.Now().Unix()
	defaultConfigModel.CreateTime = time.Now().Unix()
	defaultConfigModel.Version = DefaultConfigVersion

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.DefaultCollection)
	filter := bson.M{"version": defaultConfigModel.Version, "type": defaultConfigModel.Type}
	_, err = collection.DeleteOne(context.Background(), filter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	_, err = collection.InsertOne(context.Background(), defaultConfigModel)
	if err != nil {
		ylog.Errorf("UpdateDefaultAgentConfig ERROR", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, defaultConfigModel)
	return
}
