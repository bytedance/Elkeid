package v1

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manger/biz/common"
	"github.com/bytedance/Elkeid/server/manger/biz/midware"
	"github.com/bytedance/Elkeid/server/manger/infra"
	"github.com/bytedance/Elkeid/server/manger/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

type AuthRequest struct {
	Username string `json:"username" bson:"username" binding:"required"`
	Password string `json:"password" bson:"password" binding:"required"`
}

type User struct {
	Username string `json:"username" bson:"username"`

	// The ciphertext of the original password.
	Password string `json:"password" bson:"password"`
	Salt     string `json:"salt" bson:"salt"`

	// Authority level: 0--> admin ; 1--> normal user
	Level int `json:"level" bson:"level"`
}

//Login
func Login(c *gin.Context) {
	var authRequest AuthRequest

	err := c.BindJSON(&authRequest)
	if err != nil {
		ylog.Errorf("GetToken", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)

	dbUser := &User{}
	err = userCol.FindOne(context.Background(), bson.M{"username": authRequest.Username}).Decode(dbUser)
	if err != nil {
		common.CreateResponse(c, common.AuthFailedErrorCode, fmt.Sprintf(`user not found, %s`, err.Error()))
		return
	}

	token, err := midware.CheckUser(authRequest.Username, authRequest.Password, dbUser.Salt, dbUser.Password)
	if err != nil {
		common.CreateResponse(c, common.AuthFailedErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, bson.M{"token": token})
}

func Logout(c *gin.Context) {
	common.CreateResponse(c, common.SuccessCode, nil)
}

//CreateUser create new user
func CreateUser(c *gin.Context) {
	user := c.GetString("user")

	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)

	//only admin can create user
	dbUser := &User{}
	err := userCol.FindOne(context.Background(), bson.M{"username": user}).Decode(dbUser)
	if err != nil {
		common.CreateResponse(c, common.AuthFailedErrorCode, fmt.Sprintf(`user not found, %s`, err.Error()))
		return
	}
	if dbUser.Level != 0 {
		common.CreateResponse(c, common.AuthFailedErrorCode, "permission denied")
		return
	}

	userParam := User{}
	err = c.BindJSON(&userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	userParam.Salt = infra.RandStringBytes(16)
	userParam.Password = midware.GenPassword(userParam.Password, userParam.Salt)
	userParam.Level = 1
	_, err = userCol.InsertOne(context.Background(), userParam)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}
