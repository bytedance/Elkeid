package v6

import (
	"net/http"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/gin-gonic/gin"
)

// ResponseStuct Response 常规返回值
type ResponseStuct struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

// PageResponseStruct PageResponse 带分页的返回
type PageResponseStruct struct {
	Code     int                 `json:"code"`
	Message  string              `json:"msg"`
	Data     interface{}         `json:"data"`
	PageInfo common.PageResponse `json:"page_info"`
}

// CreateResponse 创建返回数据
func CreateResponse(c *gin.Context, code int, data interface{}) {
	var response ResponseStuct
	response.Code = code
	if msg, ok := common.ErrorDescriptions[code]; ok {
		response.Message = msg
	}
	response.Data = data
	c.JSON(
		http.StatusOK,
		response,
	)
}

// CreatePageResponse 创建分页返回数据
func CreatePageResponse(c *gin.Context, code int, data interface{}, page common.PageResponse) {
	var response PageResponseStruct
	response.Code = code
	if msg, ok := common.ErrorDescriptions[code]; ok {
		response.Message = msg
	}
	response.Data = data
	response.PageInfo = page
	c.JSON(
		http.StatusOK,
		response,
	)
}
