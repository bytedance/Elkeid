// Package login implements all login management interfaces.
package login

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"sync"
	"time"
)

type User struct {
	Username           string       `json:"username" bson:"username"`
	Password           string       `json:"password" bson:"password"`
	Salt               string       `json:"salt" bson:"salt"`
	Avatar             string       `json:"avatar" bson:"avatar"`
	Level              int          `json:"level" bson:"level"` // 权限等级 0-->admin; 1-->高级用户(agent读写+hub读写)； 2-->agent读写；3-->agent只读；4-->hub读写；5-->hub只读
	Config             []UserConfig `json:"config" bson:"config"`
	Xml                bool         `json:"xml" bson:"xml"`
	PasswordUpdateTime int64        `json:"password_update_time" bson:"password_update_time"`
}

type UserConfig struct {
	Workspace string              `json:"workspace" bson:"workspace"`
	Favor     map[string][]string `json:"favor" bson:"favor"`
}

// 权限等级 0-->admin; 1-->高级用户(agent读写+hub读写)； 2-->agent读写；3-->agent只读；4-->hub读写；5-->hub只读
var (
	UserTable map[string]*User
	UserLock  sync.RWMutex
)

const LoginSessionTimeoutMin = 120

// GetUser find the user in the cache and returns, if user not exist, return nil.
// This interface is high-performance, but may not be up-to-date.
func GetUser(userName string) *User {
	UserLock.RLock()
	defer UserLock.RUnlock()
	user, ok := UserTable[userName]
	if !ok {
		return nil
	}
	return user
}

// GetUserFromDB find the user in db and returns, if user not exist, return nil.
func GetUserFromDB(userName string) (*User, error) {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	var user User
	err := col.FindOne(context.Background(), bson.M{"username": userName}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetLoginSessionTimeoutMinute returns the login session idle timeout time in minutes.
func GetLoginSessionTimeoutMinute() int64 {
	return LoginSessionTimeoutMin
}

func initUser() {
	table := loadUserFromDB()
	if table != nil {
		UserLock.Lock()
		UserTable = table
		UserLock.Unlock()
	}

	go func() {
		for {
			time.Sleep(3 * time.Second)
			table := loadUserFromDB()
			if table != nil {
				UserLock.Lock()
				UserTable = table
				UserLock.Unlock()
			}
		}
	}()
}

func loadUserFromDB() map[string]*User {
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	cur, err := userCol.Find(context.Background(), bson.M{})
	if err != nil {
		ylog.Errorf("loadUserFromDB", err.Error())
		return nil
	}
	defer func() {
		_ = cur.Close(context.Background())
	}()

	userTable := map[string]*User{}
	for cur.Next(context.Background()) {
		var user User
		err := cur.Decode(&user)
		if err != nil {
			ylog.Errorf("loadUserFromDB", err.Error())
			continue
		}
		userTable[user.Username] = &user
	}
	return userTable
}
