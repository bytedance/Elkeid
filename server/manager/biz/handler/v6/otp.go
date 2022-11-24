package v6

import (
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/gin-gonic/gin"
)

func GetUserOTPStatus(c *gin.Context) {
	_, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	var userResult = struct {
		OTPEnable bool `bson:"otp_enable" json:"otp_enable"`
	}{}
	userResult.OTPEnable = true
	common.CreateResponse(c, common.SuccessCode, userResult)
}
