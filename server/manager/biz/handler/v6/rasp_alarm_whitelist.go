package v6

import (
	"github.com/bytedance/Elkeid/server/manager/internal/alarm_whitelist"
	"github.com/gin-gonic/gin"
)

func MultiDelWhiteListForRasp(c *gin.Context) {
	WhiteListDelMulti(c, alarm_whitelist.WhitelistTypeRasp)
}

func GetWhiteListWithCombineForRasp(c *gin.Context) {
	GetWhiteListWithCombine(c, alarm_whitelist.WhitelistTypeRasp)
}

func MultiAddWhiteListWithCombineForRasp(c *gin.Context) {
	WhiteListAddMultiWithCombine(c, alarm_whitelist.WhitelistTypeRasp)
}

func WhiteListUpdateOneForRasp(c *gin.Context) {
	WhiteListUpdateOne(c, alarm_whitelist.WhitelistTypeRasp)
}
