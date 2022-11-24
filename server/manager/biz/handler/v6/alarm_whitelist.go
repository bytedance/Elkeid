package v6

import (
	"github.com/bytedance/Elkeid/server/manager/internal/alarm_whitelist"
	"github.com/gin-gonic/gin"
)

// ############################### Function ###############################
func MultiDelWhiteListForHids(c *gin.Context) {
	WhiteListDelMulti(c, alarm_whitelist.WhitelistTypeHids)
}

func GetWhiteListWithCombineForHids(c *gin.Context) {
	GetWhiteListWithCombine(c, alarm_whitelist.WhitelistTypeHids)
}

func MultiAddWhiteListWithCombineForHids(c *gin.Context) {
	WhiteListAddMultiWithCombine(c, alarm_whitelist.WhitelistTypeHids)
}

func WhiteListUpdateOneForHids(c *gin.Context) {
	WhiteListUpdateOne(c, alarm_whitelist.WhitelistTypeHids)
}
