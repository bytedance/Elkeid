package midware

import (
	"context"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"go.mongodb.org/mongo-driver/bson"
)

//权限等级 0-->admin; 1-->高级用户(agent读写+hub读写)； 2-->agent读写；3-->agent只读；4-->hub读写；5-->hub只读

var (
	UserTable map[string]*User
	userLock  sync.RWMutex

	ACWorker *AcController
)

func init() {
	var err error
	table := loadUserFromDB()
	if table != nil {
		userLock.Lock()
		UserTable = table
		userLock.Unlock()
	}

	ACWorker, err = NewAcController("conf/rbac.json")
	if err != nil {
		ylog.Errorf("NewAcController", "error %s", err.Error())
	}

	go func() {
		for {
			time.Sleep(60 * time.Second)

			table := loadUserFromDB()
			if table != nil {
				userLock.Lock()
				UserTable = table
				userLock.Unlock()
			}
		}
	}()
}

func loadUserFromDB() map[string]*User {
	userCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.UserCollection)
	cur, err := userCol.Find(context.Background(), bson.M{})
	if err != nil {
		ylog.Errorf("loadUserFromDB", err.Error())
		return nil
	}
	defer cur.Close(context.Background())

	userTable := map[string]*User{}
	for cur.Next(context.Background()) {
		var user User
		err := cur.Decode(&user)
		if err != nil {
			ylog.Errorf("loadUserFromDB", err.Error())
			continue
		}
		userTable[user.Username] = &user
	}
	return userTable
}
func LoadUserFromDB() {
	table := loadUserFromDB()
	if table != nil {
		userLock.Lock()
		UserTable = table
		userLock.Unlock()
	}
	return
}
func queryRolesByHeaders(c *gin.Context) (role string) {
	user, ok := c.Get("user")
	if !ok {
		return ""
	}
	return user.(string)
}

type MetaRule struct {
	ID              int      `json:"id" yaml:"id"`
	Desc            string   `json:"desc" yaml:"desc"`
	PathEqual       []string `json:"path_equal" yaml:"path_equal"`
	PathPre         []string `json:"path_pre" yaml:"path_pre"`
	PathRegex       []string `json:"path_regex" yaml:"path_regex"`
	AuthorizedRoles []int    `json:"authorized_roles" yaml:"authorized_roles"`
	AllowAnyone     bool     `json:"allow_anyone" yaml:"allow_anyone"`
}

type AcRule struct {
	rule *MetaRule

	pathRegexList []*regexp.Regexp
	roleMap       map[int]bool
}

func NewAcRule(rule *MetaRule) *AcRule {
	c := &AcRule{
		rule:          rule,
		pathRegexList: make([]*regexp.Regexp, 0),
		roleMap:       make(map[int]bool),
	}

	for _, v := range rule.PathRegex {
		reg, err := regexp.Compile(v)
		if err != nil {
			ylog.Errorf("RBACAuth", "regex parse rule %s error %s", v, err.Error())
			continue
		}
		c.pathRegexList = append(c.pathRegexList, reg)
	}

	for _, v := range rule.AuthorizedRoles {
		c.roleMap[v] = true
	}

	return c
}

func (c *AcRule) MatchPath(path string) bool {
	for _, v := range c.rule.PathEqual {
		if v == path {
			return true
		}
	}

	for _, v := range c.rule.PathPre {
		if strings.HasPrefix(path, v) {
			return true
		}
	}

	for _, v := range c.pathRegexList {
		if v.MatchString(path) {
			return true
		}
	}
	return false
}

func (c *AcRule) MatchRole(role string) bool {
	if c.rule.AllowAnyone {
		return true
	}

	user, ok := UserTable[role]
	if !ok {
		return false
	}
	//fmt.Printf("role %s user %#v user %#v\n", role, *user, c.roleMap)
	if _, ok := c.roleMap[user.Level]; ok {
		return true
	}
	return false
}

type AcController struct {
	ruleList []*AcRule
}

func NewAcController(fileName string) (*AcController, error) {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	rules := make([]MetaRule, 0)
	err = jsoniter.Unmarshal(bytes, &rules)
	if err != nil {
		return nil, err
	}

	a := &AcController{ruleList: make([]*AcRule, 0, len(rules))}
	//sort by id
	sort.Slice(rules, func(i, j int) bool {
		return RuleIDSort(rules[i], rules[j])
	})

	for k, _ := range rules {
		a.ruleList = append(a.ruleList, NewAcRule(&rules[k]))
	}
	return a, nil
}

func (a *AcController) IsRequestGranted(path, role string) bool {
	for _, v := range a.ruleList {
		if v.MatchPath(path) {
			//fmt.Printf("path %s rule %#v\n", path, *v.rule)
			return v.MatchRole(role)
		}
	}
	return true
}

func RuleIDSort(one MetaRule, other MetaRule) bool {
	if one.ID > other.ID {
		return true
	} else {
		return false
	}
}

func RBACAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if ACWorker == nil {
			ylog.Debugf("RBACAuth", "ACWorker Is nil %s, all request will be passed")
			c.Next()
			return
		}

		if !ACWorker.IsRequestGranted(c.Request.URL.Path, queryRolesByHeaders(c)) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
}
