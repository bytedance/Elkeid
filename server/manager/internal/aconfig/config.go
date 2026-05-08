package aconfig

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

const DefaultConfigVersion = 0
const DefaultAgentConfig = "agent_config"

// DefaultConfig : old version default config ( no version )
type DefaultConfig struct {
	Type       string           `json:"type" bson:"type" binding:"required"`
	Version    int              `json:"version" bson:"version"`
	Config     []AgentConfigMsg `json:"config" bson:"config" binding:"required"`
	CreateTime int64            `json:"create_time" bson:"create_time"`
	UpdateTime int64            `json:"update_time" bson:"update_time"`
}

// DefaultVersionConfig : new version default config with special version.(火山引擎专用代码)
type DefaultVersionConfig struct {
	Type       string           `json:"type" bson:"type" binding:"required"`
	Version    string           `json:"version" bson:"version"`
	Config     []AgentConfigMsg `json:"config" bson:"config" binding:"required"`
	CreateTime int64            `json:"create_time" bson:"create_time"`
	UpdateTime int64            `json:"update_time" bson:"update_time"`
}

func GetDefaultConfig() []AgentConfigMsg {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.DefaultCollection)
	var config DefaultConfig
	filter := bson.M{"type": DefaultAgentConfig, "version": DefaultConfigVersion}
	err := collection.FindOne(context.Background(), filter).Decode(&config)
	if err != nil {
		ylog.Infof("GetDefaultConfig", "default config is not set, now use empty config, error is : %s", err.Error())
		return []AgentConfigMsg{}
	}
	return config.Config
}

func GetConfigByID(agentID string) ([]AgentConfigMsg, error) {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	var hb AgentHBInfo
	filter := bson.M{"agent_id": agentID}
	err := collection.FindOne(context.Background(), filter).Decode(&hb)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}

	if hb.Config == nil || len(hb.Config) == 0 {
		//Read the default version
		return GetDefaultConfig(), nil
	}
	return hb.Config, nil
}

// UpdateDefaultConfig update default agent config
func UpdateDefaultConfig(conf DefaultConfig) error {
	conf.UpdateTime = time.Now().Unix()
	conf.Type = DefaultAgentConfig
	conf.Version = DefaultConfigVersion
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.DefaultCollection)
	filter := bson.M{"version": conf.Version, "type": conf.Type}
	_, err := collection.UpdateOne(context.Background(), filter, bson.M{"$set": bson.M{"config": conf.Config, "update_time": conf.UpdateTime}, "$setOnInsert": bson.M{"create_time": time.Now().Unix()}})
	if err != nil {
		return err
	}
	return nil
}

//火山引擎专用代码

// GetDefaultVersionConfig get default agent config by version

// GetVersionConfigByID return agent config by agent_id. which the config is match for special version
