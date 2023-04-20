package v1

import (
	"context"
	"crypto/sha1"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/internal/login"
	"io"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func UserLoginout(c *gin.Context) {
	token := c.GetHeader("token")
	err := infra.Grds.Del(context.Background(), token).Err()
	if err != nil {
		common.CreateResponse(c, common.SuccessCode, err.Error())
	} else {
		common.CreateResponse(c, common.SuccessCode, nil)
	}
}

func UserLogin(c *gin.Context) {
	var user AuthRequest

	err := c.BindJSON(&user)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	if user.Username == "root" {
		//使用jwt token
		_, err := midware.CheckUser(user.Username, user.Password)
		if err != nil {
			common.CreateResponse(c, common.AuthFailedErrorCode, err.Error())
			return
		}
		token, err := midware.GeneralJwtToken(user.Username)
		if err != nil {
			common.CreateResponse(c, common.AuthFailedErrorCode, err.Error())
			return
		}
		common.CreateResponse(c, common.SuccessCode, bson.M{"token": token})
		return
	}

	_, err = midware.CheckUser(user.Username, user.Password)
	//密码校验
	if err != nil {
		common.CreateResponse(c, common.AuthFailedErrorCode, "verify password failed")
	} else {
		token := midware.GeneralSession()
		err = infra.Grds.Set(context.Background(), token, user.Username, time.Duration(login.GetLoginSessionTimeoutMinute())*time.Minute).Err()
		if err != nil {
			ylog.Errorf("UserLogin", "Set %s redis error %s", user.Username, err.Error())
		}
		common.CreateResponse(c, common.SuccessCode, bson.M{"token": token})
	}
}

func UserInfo(c *gin.Context) {
	userName := c.GetString("user")
	if userName == "" {
		common.CreateResponse(c, common.SuccessCode, bson.M{"avatar": "", "name": ""})
		return
	}
	user, err := login.GetUserFromDB(userName)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	user.Password = "***"
	user.Salt = "***"
	common.CreateResponse(c, common.SuccessCode, user)
}

// UpdateUser 管理员可操作
func UpdateUser(c *gin.Context) {
	userParam := login.User{}
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
	_, err = userCol.UpdateOne(
		context.Background(),
		bson.M{"username": userParam.Username},
		bson.M{"$set": bson.M{
			"level":  userParam.Level,
			"avatar": userParam.Avatar,
		}},
	)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

// DelUser 管理员可操作
func DelUser(c *gin.Context) {
	userParam := login.User{}
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

// ResetPassword 用户本身可操作
func ResetPassword(c *gin.Context) {
	userParam := login.User{}
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
	userParam.PasswordUpdateTime = time.Now().Unix()
	_, err = userCol.UpdateOne(context.Background(), bson.M{"username": userParam.Username},
		bson.M{"$set": bson.M{"salt": userParam.Salt, "password": userParam.Password, "password_update_time": userParam.PasswordUpdateTime}})
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}

// CheckPassword 验证用户密码,用户本身可操作
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
	user, err := login.GetUserFromDB(authRequest.Username)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	t := sha1.New()
	_, err = io.WriteString(t, authRequest.Password+user.Salt)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	if fmt.Sprintf("%x", t.Sum(nil)) == user.Password {
		common.CreateResponse(c, common.SuccessCode, bson.M{"if_check": true})
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"if_check": false})
}

// CreateUserV6 管理员可操作
func CreateUserV6(c *gin.Context) {
	userParam := login.User{}
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
		var userodj login.User
		err := userCol.FindOne(c, bson.M{"username": userParam.Username}).Decode(&userodj)
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		level := userodj.Level
		if level != 0 && level != 2 && level != 3 {
			common.CreateResponse(c, common.DuplicateFieldErrorCode, "username locking, please change")
		} else {
			//common.CreateResponse(c, common.DuplicateFieldErrorCode, "username duplicate")
			common.CreateResponse(c, common.DuplicateFieldErrorCode, "用户名重复")
		}
		return
	}

	userParam.Salt = infra.RandStringBytes(16)
	userParam.Password = midware.GenPassword(userParam.Password, userParam.Salt)
	userParam.PasswordUpdateTime = time.Now().Unix()
	_, err = userCol.InsertOne(context.Background(), userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}
