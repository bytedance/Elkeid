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
	UnknownErrorCode
	RemoteServerError
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
	UnknownErrorCode:         "unknown error",
	RemoteServerError:        "remote server error",
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
