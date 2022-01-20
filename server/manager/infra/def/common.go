package def

import (
	"context"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"go.mongodb.org/mongo-driver/bson"
)

type User struct {
	Username string       `json:"username" bson:"username"`
	Password string       `json:"password" bson:"password"`
	Salt     string       `json:"salt" bson:"salt"`
	Avatar   string       `json:"avatar" bson:"avatar"`
	Level    int          `json:"level" bson:"level"` //权限等级 0-->admin; 1-->高级用户(agent读写+hub读写)； 2-->agent读写；3-->agent只读；4-->hub读写；5-->hub只读
	Config   []UserConfig `json:"config" bson:"config"`
	Xml      bool         `json:"xml" bson:"xml"`
}
type UserConfig struct {
	Workspace string              `json:"workspace" bson:"workspace"`
	Favor     map[string][]string `json:"favor" bson:"favor"`
}

func StarComponentCommon(c context.Context, user, component, comType, star, workSpace string) error {
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	var userodj User
	err := userCol.FindOne(c, bson.M{"username": user}).Decode(&userodj)
	if err != nil {
		return err
	}
	if component == "" || comType == "" || star == "" {
		return fmt.Errorf("params invalid")
	}
	workspaceIndex := -1
	for k, v := range userodj.Config {
		if v.Workspace == workSpace {
			workspaceIndex = k
		}
	}

	if star == "1" {
		if workspaceIndex == -1 {
			favorMap := getFavorMap()
			favorList := make([]string, 0)
			favorList = append(favorList, component)
			favorMap[comType] = favorList
			newConfig := UserConfig{
				workSpace, favorMap,
			}
			userodj.Config = append(userodj.Config, newConfig)
		} else {
			v, _ := userodj.Config[workspaceIndex].Favor[comType]
			for _, value := range v {
				if value == component {
					return nil
				}
			}
			favorList := make([]string, 0)
			favorList = append(v, component)
			userodj.Config[workspaceIndex].Favor[comType] = favorList
		}
	} else if star == "0" {
		if workspaceIndex == -1 {
			favorMap := getFavorMap()
			newConfig := UserConfig{
				workSpace, favorMap,
			}
			userodj.Config = append(userodj.Config, newConfig)
		} else {
			v, _ := userodj.Config[workspaceIndex].Favor[comType]
			for key, value := range v {
				if value == component {
					userodj.Config[workspaceIndex].Favor[comType] = append(v[:key], v[key+1:]...)
					break
				}
			}
		}
	}
	userCol = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()
	err = userCol.FindOneAndReplace(ctx, bson.M{"username": userodj.Username}, userodj).Err()
	return err
}

func getFavorMap() (favorMap map[string][]string) {
	favorMap = make(map[string][]string, 7)
	favorMap["input"] = []string{}
	favorMap["output"] = []string{}
	favorMap["project"] = []string{}
	favorMap["ruleset"] = []string{}
	favorMap["datasource"] = []string{}
	favorMap["debug_config"] = []string{}
	favorMap["debug_task"] = []string{}
	favorMap["connector"] = []string{}
	return
}
