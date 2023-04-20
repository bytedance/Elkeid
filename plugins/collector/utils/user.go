package utils

import (
	"math/rand"
	"os/user"

	"github.com/coocood/freecache"
)

const (
	userCacheExpiration = 3 * 3600
)

var ( // username cache
	uc = freecache.NewCache(256)
	gc = freecache.NewCache(256)
)

func GetUsername(uid string) (ret string, err error) {
	if u, ok := uc.Get([]byte(uid)); ok == nil {
		ret = string(u)
	} else {
		var u *user.User
		u, err = user.LookupId(uid)
		if err != nil {
			return
		}
		ret = u.Username
		uc.Set([]byte(uid), []byte(ret), userCacheExpiration+rand.Intn(userCacheExpiration))
	}
	return
}
func GetGroupname(gid string) (ret string, err error) {
	if g, ok := gc.Get([]byte(gid)); ok == nil {
		ret = string(g)
	} else {
		var g *user.Group
		g, err = user.LookupGroupId(gid)
		if err != nil {
			return
		}
		ret = g.Name
		gc.Set([]byte(gid), []byte(ret), userCacheExpiration+rand.Intn(userCacheExpiration))
	}
	return
}
