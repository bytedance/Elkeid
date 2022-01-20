package v1

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

type AuthRequest struct {
	Username string `json:"username" bson:"username" binding:"required"`
	Password string `json:"password" bson:"password" binding:"required"`
}

func UserLoginout(c *gin.Context) {
	common.CreateResponse(c, common.SuccessCode, nil)
}

func UserLogin(c *gin.Context) {
	var authRequest AuthRequest

	err := c.BindJSON(&authRequest)
	if err != nil {
		ylog.Errorf("GetToken", err.Error())
		return
	}

	user, ok := midware.UserTable[authRequest.Username]
	if !ok {
		common.CreateResponse(c, common.AuthFailedErrorCode, nil)
		return
	}

	token, err := midware.CheckUser(authRequest.Username, authRequest.Password, user.Salt, user.Password)
	if err != nil {
		common.CreateResponse(c, common.AuthFailedErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, bson.M{"token": token})
}

func UserInfo(c *gin.Context) {
	user, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.SuccessCode, bson.M{"avatar": "", "name": ""})
		return
	}
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	var userodj User
	err := userCol.FindOne(context.Background(), bson.M{"username": user}).Decode(&userodj)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	//
	if !ok {
		common.CreateResponse(c, common.SuccessCode, bson.M{"avatar": "", "name": ""})
	} else {
		userobj := User{
			Username: userodj.Username,
			Password: "***",
			Salt:     "***",
			Avatar:   userodj.Avatar,
			Level:    userodj.Level,
			Xml:      userodj.Xml,
			Config:   userodj.Config,
		}
		common.CreateResponse(c, common.SuccessCode, userobj)
	}
}
func ModEditor(c *gin.Context) {
	user, ok := c.Get("user")
	isXml := c.Query("xml")
	if !ok {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user info")
		return
	}
	userodj, ok := midware.UserTable[user.(string)]
	if isXml == "1" {
		userodj.Xml = true
	} else if isXml == "0" {
		userodj.Xml = false
	}
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	_, err := userCol.UpdateOne(context.Background(), bson.M{"username": userodj.Username},
		bson.M{"$set": bson.M{"xml": userodj.Xml}})
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

func UserList(c *gin.Context) {
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	cur, err := userCol.Find(c, bson.M{})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	userList := make([]User, 0)
	err = cur.All(c, &userList)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	for k, _ := range userList {
		userList[k].Salt = "***"
		userList[k].Password = "***"
	}
	common.CreateResponse(c, common.SuccessCode, userList)
}

//管理员可操作
func CreateUser(c *gin.Context) {
	userParam := User{}
	err := c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)

	count, err := userCol.CountDocuments(c, bson.M{"username": userParam.Username})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if count != 0 {
		common.CreateResponse(c, common.DuplicateFieldErrorCode, "username duplicate")
		return
	}

	userParam.Salt = infra.RandStringBytes(16)
	userParam.Password = midware.GenPassword(userParam.Password, userParam.Salt)
	_, err = userCol.InsertOne(context.Background(), userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

//管理员可操作
func UpdateUser(c *gin.Context) {
	userParam := User{}
	err := c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)

	count, err := userCol.CountDocuments(c, bson.M{"username": userParam.Username})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if count != 1 {
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("user is not in db, count :%d", count))
		return
	}

	_, err = userCol.UpdateOne(context.Background(), bson.M{"username": userParam.Username},
		bson.M{"$set": bson.M{"level": userParam.Level, "avatar": userParam.Avatar}})
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

//管理员可操作
func DelUser(c *gin.Context) {
	userParam := User{}
	err := c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	_, err = userCol.DeleteOne(c, bson.M{"username": userParam.Username})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

//用户本身可操作
func ResetPassword(c *gin.Context) {
	userParam := User{}
	err := c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if userParam.Password == "" {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "password cannot be empty")
		return
	}
	user, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}

	//用户本身可以修改
	if user.(string) != userParam.Username {
		common.CreateResponse(c, common.UnknownErrorCode, "permission denied")
		return
	}

	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)

	count, err := userCol.CountDocuments(c, bson.M{"username": userParam.Username})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if count != 1 {
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("user is not in db, count :%d", count))
		return
	}

	userParam.Salt = infra.RandStringBytes(16)
	userParam.Password = midware.GenPassword(userParam.Password, userParam.Salt)
	_, err = userCol.UpdateOne(context.Background(), bson.M{"username": userParam.Username},
		bson.M{"$set": bson.M{"salt": userParam.Salt, "password": userParam.Password}})
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

// 验证用户密码,用户本身可操作
func CheckPassword(c *gin.Context) {
	var authRequest AuthRequest

	err := c.BindJSON(&authRequest)
	if err != nil {
		ylog.Errorf("CheckPassword", err.Error())
		return
	}

	//用户本身可以修改
	operateUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	if operateUser.(string) != authRequest.Username {
		common.CreateResponse(c, common.UnknownErrorCode, "permission denied")
		return
	}

	// 验证密码
	user, ok := midware.UserTable[authRequest.Username]
	if !ok {
		common.CreateResponse(c, common.AuthFailedErrorCode, nil)
		return
	}

	t := sha1.New()
	io.WriteString(t, authRequest.Password+user.Salt)
	if fmt.Sprintf("%x", t.Sum(nil)) == user.Password {
		common.CreateResponse(c, common.SuccessCode, bson.M{"if_check": true})
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"if_check": false})
}

//管理员可操作
func CreateUserV6(c *gin.Context) {
	userParam := User{}
	err := c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)

	count, err := userCol.CountDocuments(c, bson.M{"username": userParam.Username})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if count != 0 {
		var userodj User
		err := userCol.FindOne(c, bson.M{"username": userParam.Username}).Decode(&userodj)
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		level := userodj.Level
		if level != 0 && level != 2 && level != 3 {
			common.CreateResponse(c, common.DuplicateFieldErrorCode, "username locking, please change")
		} else {
			common.CreateResponse(c, common.DuplicateFieldErrorCode, "username duplicate")
		}
		return
	}

	userParam.Salt = infra.RandStringBytes(16)
	userParam.Password = midware.GenPassword(userParam.Password, userParam.Salt)
	_, err = userCol.InsertOne(context.Background(), userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}
