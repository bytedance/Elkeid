package common

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

const (
	SuccessCode = iota
	AuthFailedErrorCode
	DuplicateFieldErrorCode
	DBOperateErrorCode
	RedisOperateErrorCode
	ParamInvalidErrorCode
	DBNoRowAffectedErrorCode
	TemporarilyUnavailable
	ErrorIDLen
	ErrorID
	UnknownErrorCode
	TimeOutErrorCode
	RemoteAllFailedErrorCode
	ProjectIDRespect
	SomeFieldIsNull
	ExceedLimitErrorCode
	SSO_ERROR
	OTPErrorCode
	PasswordNeedChanged
	NeedCaptchaCheck
	LoginIpNotInWhiteList
	UserLocked
)

var ErrorDescriptions = map[int]string{
	SuccessCode:              "success",
	AuthFailedErrorCode:      "auth failed",
	DuplicateFieldErrorCode:  "duplicate field",
	DBOperateErrorCode:       "db operate error",
	RedisOperateErrorCode:    "redis operate error",
	ParamInvalidErrorCode:    "param invalid",
	DBNoRowAffectedErrorCode: "db no row affected",
	TemporarilyUnavailable:   "resource temporarily unavailable",
	ErrorIDLen:               "ID MAX LEN IS 1-15",
	ErrorID:                  "ID ONLY SYUUPRT 'A-Z/a-z/0-9/-/_'",
	UnknownErrorCode:         "unknown error",
	ProjectIDRespect:         "PROJECT ID REPECT",
	SomeFieldIsNull:          "SOME FIELD IS NUL",
	TimeOutErrorCode:         "get result timeout",
	RemoteAllFailedErrorCode: "all remote instance failed",
	SSO_ERROR:                "sso error",
	OTPErrorCode:             "otp required",
	PasswordNeedChanged:      "password has not been updated for a long time",
	NeedCaptchaCheck:         "need captcha check",
	LoginIpNotInWhiteList:    "login ip not in whitelist",
	UserLocked:               "user locked",
}

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

func (response *Response) SetError(code int) {
	response.Code = code

	if msg, ok := ErrorDescriptions[code]; ok {
		response.Message = msg
	}
}

func CreateResponse(c *gin.Context, code int, data interface{}) {
	var response Response

	response.SetError(code)
	response.Data = data
	c.JSON(
		http.StatusOK,
		response,
	)
}
