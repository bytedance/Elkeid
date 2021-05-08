package http_handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

const (
	SuccessCode = iota
	AuthFailedErrorCode
	ParamInvalidErrorCode
	UnknownErrorCode
)

var ErrorDescriptions = map[int]string{
	SuccessCode:           "success",
	AuthFailedErrorCode:   "auth failed",
	ParamInvalidErrorCode: "param invalid",
	UnknownErrorCode:      "some errors occurred",
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
