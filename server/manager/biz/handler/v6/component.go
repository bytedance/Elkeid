package v6

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin/binding"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	versionRegex, _                 = regexp.Compile(`^(([1-9]\d{0,3}|0)\.){3}([1-9]\d{0,3}|0)$`)
	nameRegex, _                    = regexp.Compile(`^[0-9A-Za-z_\-]+$`)
	versionValidator validator.Func = func(fl validator.FieldLevel) bool {
		return versionRegex.MatchString(fl.Field().String())
	}
	regexCache    = &sync.Map{}
	policiesCache = &atomic.Value{}
	tagsCache     = sync.Map{}
)

type localPolicies struct {
	t        int64
	policies []*Policy
}

func InitComponent() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		err := v.RegisterValidation("component_version", versionValidator)
		if err != nil {
			ylog.Errorf("InitComponent", "RegisterValidation error %s", err.Error())
		}
	}

	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	for {
		ylog.Infof("[Component Tags Cache]", "refresh cache")
		coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		cursor, err := coll.Aggregate(context.Background(), bson.A{
			// active in latest 24h
			bson.M{
				"$match": bson.M{
					"last_heatrbeat_time": bson.M{
						"$gt": time.Now().Unix() - 24*60*60,
					},
				},
			},
			bson.M{
				"$project": bson.M{
					"agent_id": 1,
					"tags":     1,
				},
			},
		})
		if err != nil {
			ylog.Errorf("[Component Tags Cache]", "refresh cache failed: %v", err.Error())
			continue
		}
		for cursor.Next(context.Background()) {
			ci := ContextInfo{}
			err = cursor.Decode(&ci)
			if err != nil {
				continue
			}
			if ci.Tags == nil {
				ci.Tags = []string{}
			}
			tagsCache.Store(ci.AgentID, ci.Tags)
		}
		ylog.Infof("[Component Tags Cache]", "refresh cache done")
		<-ticker.C
	}
}

const (
	MaxComponentSize = 512 * 1024 * 1024
)

type CreateComponentReqBody struct {
	Name                       string   `json:"name" binding:"required_unless=Type agent"`
	Type                       string   `json:"type" binding:"required,oneof=tar.gz exec agent"`
	ArchRequirements           []string `json:"arch_requirements" bson:"arch_requirements" binding:"required,max=2,unique,dive,oneof=x86_64 aarch64"`
	PlatformFamilyRequirements []string `json:"platform_family_requirements" bson:"platform_family_requirements" binding:"required,max=2,unique,dive,oneof=debian rhel"`
}
type PublishComponentVersionReqBody struct {
	ComponentID string `json:"component_id" form:"component_id" binding:"required"`
	Version     string `json:"version" form:"version" binding:"required,component_version"`
}
type Component struct {
	ID                         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name                       string             `json:"name" bson:"name"`
	Type                       string             `json:"type" bson:"type"`
	ArchRequirements           []string           `json:"arch_requirements" bson:"arch_requirements"`
	PlatformFamilyRequirements []string           `json:"platform_family_requirements" bson:"platform_family_requirements"`
	Owner                      string             `json:"owner" bson:"owner"`
	CreateTime                 int                `json:"create_time" bson:"create_time"`
	LatestPublishTime          int                `json:"latest_publish_time" bson:",omitempty"`
	LatestPublishVersion       string             `json:"latest_publish_version" bson:",omitempty"`
	LatestPublisher            string             `json:"latest_publisher" bson:",omitempty"`
}
type ComponentVersion struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Version     string             `json:"version" bson:"version"`
	Files       []ComponentFile    `json:"files" bson:"files"`
	Publisher   string             `json:"publisher" bson:"publisher"`
	PublishTime int                `json:"publish_time" bson:"publish_time"`
	Component   Component          `json:"component" bson:"component"`
}
type ComponentFile struct {
	PlarformFamily string   `json:"platform_family" bson:"platform_family"`
	Arch           string   `json:"arch" bson:"arch"`
	DownloadURL    []string `json:"download_url" bson:"download_url"`
	SHA256         string   `json:"sha256" bson:"sha256"`
	Signature      string   `json:"signature" bson:"signature"`
}
type ComponentInstance struct {
	Name        string   `json:"name" bson:"name"`
	Version     string   `json:"version" bson:"version"`
	SHA256      string   `json:"sha256" bson:"sha256"`
	DownloadURL []string `json:"download_url" bson:"download_url"`
	Signature   string   `json:"signature" bson:"signature"`
	Type        string   `json:"type" bson:"type"`
}

func (p *Policy) GetIntance(info *ContextInfo) (*ComponentInstance, error) {
	i := &ComponentInstance{
		Name:    p.Component.Name,
		Type:    p.Component.Type,
		Version: p.Version,
	}
	if info.AgentID != "" {
		for _, rule := range p.Rules {
			var v interface{}
			switch rule.Key {
			case "agent_id":
				v = info.AgentID
			case "tag":
				var ok bool
				v, ok = tagsCache.Load(info.AgentID)
				if !ok {
					coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
					s := coll.FindOne(context.Background(), bson.M{"agent_id": info.AgentID}, options.FindOne().SetProjection(bson.M{"agent_id": 1, "tags": 1}))
					tmpInfo := ContextInfo{}
					err := s.Decode(&tmpInfo)
					if err != nil {
						ylog.Errorf("[Component GetIntance]", "get tags faield: %v", err.Error())
					} else {
						v = tmpInfo.Tags
						tagsCache.Store(info.AgentID, tmpInfo.Tags)
					}
				}
			case "kernel_version":
				v = info.KernelVersion
			default:
				ylog.Errorf("[Component GetIntance]", "componenet policy rule unknown key: %v", rule.Key)
			}
			find, err := rule.Find(v)
			if err != nil {
				ylog.Errorf("[Component GetIntance]", "componenet policy rule find error: %v", err.Error())
			}
			if find {
				return nil, fmt.Errorf("shot on the block policy: %v", info)
			}
		}
	}
	set := false
	for _, f := range p.Files {
		if (len(p.Component.ArchRequirements) == 0 && len(p.Component.PlatformFamilyRequirements) == 0) ||
			((len(p.Component.ArchRequirements) != 0 && len(p.Component.PlatformFamilyRequirements) != 0) && (info.PlatformFamily == f.PlarformFamily && info.Arch == f.Arch)) ||
			((len(p.Component.ArchRequirements) != 0 && len(p.Component.PlatformFamilyRequirements) == 0) && (info.Arch == f.Arch)) ||
			((len(p.Component.ArchRequirements) == 0 && len(p.Component.PlatformFamilyRequirements) != 0) && (info.PlatformFamily == f.PlarformFamily)) {
			i.SHA256 = f.SHA256
			i.Signature = f.Signature
			i.DownloadURL = f.DownloadURL
			set = true
			break
		}
	}
	if set {
		return i, nil
	} else {
		return nil, fmt.Errorf("get instace %v failed with %+v", p.Component.Name, info)
	}
}
func CreateComponent(c *gin.Context) {
	req := CreateComponentReqBody{}
	err := c.Bind(&req)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if req.Type == "agent" {
		req.Name = infra.AgentName
	} else {
		if nameRegex.FindString(req.Name) == "" {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "invalid component name")
			return
		}
	}
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentCollection)
	res, err := coll.UpdateOne(c,
		bson.M{"name": req.Name},
		bson.M{"$setOnInsert": Component{
			Name:                       req.Name,
			Type:                       req.Type,
			ArchRequirements:           req.ArchRequirements,
			PlatformFamilyRequirements: req.PlatformFamilyRequirements,
			Owner:                      c.GetString("user"),
			CreateTime:                 int(time.Now().Unix()),
		}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		if res.UpsertedID == nil {
			common.CreateResponse(c, common.UnknownErrorCode, "create component failed")
		} else {
			common.CreateResponse(c, common.SuccessCode, res.UpsertedID)
		}
	}
}
func PublishComponentVersion(c *gin.Context) {
	req := PublishComponentVersionReqBody{}
	err := c.Bind(&req)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	componentID, _ := primitive.ObjectIDFromHex(req.ComponentID)
	comp := Component{}
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentCollection)
	err = coll.FindOne(c, bson.M{"_id": componentID}).Decode(&comp)
	// no such component
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	// check component version
	coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentVersionCollection)
	if !errors.Is(coll.FindOne(c, bson.M{"component._id": componentID, "version": req.Version}).Err(), mongo.ErrNoDocuments) {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "version of component duplicated")
		return
	}
	var names []string
	if len(comp.ArchRequirements) == 0 && len(comp.PlatformFamilyRequirements) == 0 {
		names = []string{"default"}
	} else if len(comp.ArchRequirements) != 0 && len(comp.PlatformFamilyRequirements) != 0 {
		for _, p := range comp.PlatformFamilyRequirements {
			for _, a := range comp.ArchRequirements {
				names = append(names, fmt.Sprintf("%v_%v", p, a))
			}
		}
	} else if len(comp.ArchRequirements) != 0 {
		names = comp.ArchRequirements
	} else {
		names = comp.PlatformFamilyRequirements
	}
	var files []ComponentFile
	for _, name := range names {
		cf := ComponentFile{}
		if name == "x86_64" || name == "aarch64" {
			cf.Arch = name
		} else {
			fileds := strings.SplitN(name, "_", 2)
			switch len(fileds) {
			case 1:
				cf.PlarformFamily = fileds[0]
			case 2:
				cf.PlarformFamily = fileds[0]
				cf.Arch = fileds[1]
			}
		}
		fh, err := c.FormFile(name)
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		if fh.Size > MaxComponentSize {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "size of component exceeds limit")
			return
		}
		f, err := fh.Open()
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		content, err := io.ReadAll(f)
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		hasher := sha256.New()
		hasher.Write(content)
		cf.SHA256 = hex.EncodeToString(hasher.Sum(nil))
		if comp.Type == "tar.gz" {
			r, err := gzip.NewReader(bytes.NewReader(content))
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			tr := tar.NewReader(r)
			for {
				var f *tar.Header
				f, err = tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
					return
				}
				if comp.Name == filepath.Clean(f.Name) {
					hasher := sha256.New()
					n, err := io.Copy(hasher, tr)
					if err != nil {
						common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
						return
					}
					if n != f.Size {
						common.CreateResponse(c, common.ParamInvalidErrorCode, "invalid main file size")
						return
					}
					cf.Signature = hex.EncodeToString(hasher.Sum(nil))
					break
				}
			}
			if cf.Signature == "" {
				common.CreateResponse(c, common.ParamInvalidErrorCode, "can't find main file or invalid signature")
				return
			}
		}
		for _, client := range infra.TosClients {
			var ext = ""
			switch comp.Type {
			case "exec":
				ext = ".plg"
			case "tar.gz":
				ext = ".tar.gz"
			case "agent":
				switch cf.PlarformFamily {
				case "debian":
					ext = ".deb"
				case "rhel":
					ext = ".rpm"
				default:
					ext = ".pkg"
				}
			}
			if cf.PlarformFamily == "" {
				cf.PlarformFamily = "default"
			}
			if cf.Arch == "" {
				cf.Arch = "default"
			}
			object := fmt.Sprintf("/agent/component/%v/%v-%v-%v-%v%v", comp.Name, comp.Name, cf.PlarformFamily, cf.Arch, req.Version, ext)
			r := bytes.NewReader(content)
			urls, err := client.PutObject(c, object, fh.Size, r)
			if err != nil {
				common.CreateResponse(c, common.UnknownErrorCode, err.Error())
				return
			}
			cf.DownloadURL = append(cf.DownloadURL, urls...)
		}
		files = append(files, cf)
	}
	res, err := coll.UpdateOne(c,
		bson.M{"component._id": componentID, "version": req.Version},
		bson.M{"$setOnInsert": ComponentVersion{
			Version:     req.Version,
			Component:   comp,
			Files:       files,
			Publisher:   c.GetString("user"),
			PublishTime: int(time.Now().Unix()),
		}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		if res.UpsertedID == nil {
			common.CreateResponse(c, common.UnknownErrorCode, "create policy failed")
		} else {
			common.CreateResponse(c, common.SuccessCode, res.UpsertedID)
		}
	}
}
func DescribeComponentList(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   bson.M{},
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	coll := infra.MongoClient.Database(infra.MongoDatabase).
		Collection(infra.ComponentCollection, options.Collection().
			SetReadPreference(readpref.Primary()))
	var data []Component
	resp, err := common.DBSearchPaginate(coll, preq, func(cursor *mongo.Cursor) (err error) {
		comp := Component{}
		err = cursor.Decode(&comp)
		if err == nil {
			coll := infra.MongoClient.Database(infra.MongoDatabase).
				Collection(infra.ComponentVersionCollection, options.Collection().
					SetReadPreference(readpref.Primary()))
			cv := ComponentVersion{}
			_ = coll.FindOne(c, bson.M{"component._id": comp.ID}, options.FindOne().SetSort(bson.M{"publish_time": -1})).Decode(&cv)
			comp.LatestPublishTime = cv.PublishTime
			comp.LatestPublishVersion = cv.Version
			comp.LatestPublisher = cv.Publisher
			data = append(data, comp)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}
func DescribeComponent(c *gin.Context) {
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentCollection)
	comp := Component{}
	id, _ := primitive.ObjectIDFromHex(c.Query("id"))
	err := coll.FindOne(c, bson.M{"_id": id}).Decode(&comp)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreateResponse(c, common.SuccessCode, comp)
	}
}
func DescribeRecommendComponentVersion(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Query("component_id"))
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentVersionCollection)
	s := coll.FindOne(c, bson.M{"component._id": id}, options.FindOne().SetSort(bson.M{"version": -1}))
	if s.Err() != nil && !errors.Is(s.Err(), mongo.ErrNoDocuments) {
		common.CreateResponse(c, common.DBOperateErrorCode, s.Err().Error())
		return
	}
	if s.Err() == nil {
		cp := &ComponentVersion{}
		err := s.Decode(cp)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, s.Err().Error())
			return
		}
		splits := strings.SplitN(cp.Version, ".", 4)
		if len(splits) != 4 {
			common.CreateResponse(c, common.DBOperateErrorCode, "component has a invalid version: "+cp.Version)
			return
		}
		numSplits := [4]int{}
		for i, s := range splits {
			numSplits[i], err = strconv.Atoi(s)
			if err != nil {
				common.CreateResponse(c, common.DBOperateErrorCode, "component has a invalid version: "+cp.Version)
				return
			}
		}
		numSplits[3] += 1
		for i := 3; i > 0; i-- {
			if numSplits[i] > 9999 {
				numSplits[i] = 0
				numSplits[i-1] += 1
			}
		}
		if numSplits[0] > 9999 {
			numSplits = [4]int{9999, 9999, 9999, 9999}
		}
		version := fmt.Sprintf("%d.%d.%d.%d", numSplits[0], numSplits[1], numSplits[2], numSplits[3])
		common.CreateResponse(c, common.SuccessCode, version)
	} else {
		common.CreateResponse(c, common.SuccessCode, "0.0.0.0")
	}
}

type PolicyRule struct {
	Key      string `json:"key" bson:"key" binding:"oneof=agent_id tag kernel_version"`
	Operator string `json:"operator" bson:"operator" binding:"oneof=$in $regex"`
	Value    string `json:"value" bson:"value" binding:"required"`
}

func (r *PolicyRule) ToBson() bson.M {
	var v interface{}
	if r.Operator == "$in" {
		v = strings.Split(r.Value, ",")
	}
	if r.Key == "tag" {
		return bson.M{
			"tags": bson.M{
				r.Operator: v,
			},
		}
	}
	if r.Operator == "$regex" {
		return bson.M{
			r.Key: bson.M{
				r.Operator: primitive.Regex{
					Pattern: r.Value,
				},
			},
		}
	}
	return bson.M{
		r.Key: bson.M{
			r.Operator: v,
		},
	}
}
func (r *PolicyRule) Find(value interface{}) (bool, error) {
	if r.Operator == "$in" {
		splits := strings.Split(r.Value, ",")
		if v, ok := value.(string); ok {
			for _, split := range splits {
				if split == v {
					return true, nil
				}
			}
		}
		if v, ok := value.([]string); ok {
			for _, split := range splits {
				for _, vv := range v {
					if split == vv {
						return true, nil
					}
				}
			}
		}
	} else if r.Operator == "$regex" {
		var reg *regexp.Regexp
		if t, ok := regexCache.Load(r.Operator); ok {
			reg = t.(*regexp.Regexp)
		} else {
			var err error
			reg, err = regexp.Compile(r.Value)
			if err != nil {
				return false, err
			}
			regexCache.Store(r.Value, reg)
		}
		if v, ok := value.(string); ok {
			return reg.FindStringSubmatch(v) != nil, nil
		} else {
			return false, errors.New("unknown type")
		}
	}
	return false, nil
}

type Policy struct {
	ID               primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	ComponentVersion `json:"component_version" bson:"component_version"`
	Type             string       `json:"type" bson:"type"`
	CreateTime       int          `json:"create_time" bson:"create_time"`
	Creator          string       `json:"creator" bson:"creator"`
	Rules            []PolicyRule `json:"rules" bson:"rules"`
}
type ContextInfo struct {
	AgentID        string   `json:"agent_id" bson:"agent_id"`
	KernelVersion  string   `json:"kernel_version" bson:"kernel_version"`
	PlatformFamily string   `json:"platform_family" bson:"platform_family"`
	Arch           string   `json:"arch" bson:"arch"`
	Tags           []string `json:"tags" bson:"tags"`
}

func GetComponentInstances(c *gin.Context) {
	info := &ContextInfo{}
	err := c.BindJSON(info)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	var policies []*Policy
	if lp, ok := policiesCache.Load().(*localPolicies); ok {
		if time.Now().Unix()-lp.t < 60 {
			policies = lp.policies
		} else {
			coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentPolicyCollection)
			cursor, err := coll.Find(c, bson.M{"type": "release"})
			if err == mongo.ErrNoDocuments {
				common.CreateResponse(c, common.SuccessCode, []interface{}{})
				return
			}
			if err != nil {
				ylog.Errorf("Load component policies failed: %v, use local policy %+v instead", err.Error(), lp.policies)
				policies = lp.policies
			} else {
				err = cursor.All(c, &policies)
				if err != nil {
					ylog.Errorf("[Component]", "Load component policies failed: %v, use local policy %+v instead", err.Error(), lp.policies)
					policies = lp.policies
				} else {
					ylog.Infof("[Component]", "Refresh component policies success: %+v", policies)
					policiesCache.Store(&localPolicies{
						t:        time.Now().Unix(),
						policies: policies,
					})
				}
			}
		}
	} else {
		coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentPolicyCollection)
		cursor, err := coll.Find(c, bson.M{"type": "release"})
		if err == mongo.ErrNoDocuments {
			common.CreateResponse(c, common.SuccessCode, []interface{}{})
			return
		}
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		err = cursor.All(c, &policies)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		ylog.Infof("[Component]", "Refresh component policies success: %+v", policies)
		policiesCache.Store(&localPolicies{
			t:        time.Now().Unix(),
			policies: policies,
		})
	}
	var instances []*ComponentInstance
	for _, p := range policies {
		if i, err := p.GetIntance(info); err == nil {
			instances = append(instances, i)
		}
	}
	common.CreateResponse(c, common.SuccessCode, instances)
}

type DescribePolicyListReqBody struct{}

func DescribePolicyList(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	body := DescribePolicyListReqBody{}
	err = c.BindJSON(&body)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   body,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	coll := infra.MongoClient.Database(infra.MongoDatabase).
		Collection(infra.ComponentPolicyCollection, options.Collection().
			SetReadPreference(readpref.Primary()))
	var data []Policy
	resp, err := common.DBSearchPaginate(coll, preq, func(cursor *mongo.Cursor) error {
		p := Policy{}
		err = cursor.Decode(&p)
		if err == nil {
			data = append(data, p)
			return nil
		} else {
			return err
		}
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type CreatePolicyReqBody struct {
	ComponentVersionID primitive.ObjectID `json:"component_version_id" bson:"component_version_id" binding:"required"`
	Rules              []PolicyRule       `json:"rules" bson:"rules" binding:"dive"`
	// Type               string             `json:"type" bson:"type" binding:"oneof=release gray"`
}

func CreatePolicy(c *gin.Context) {
	body := CreatePolicyReqBody{}
	err := c.BindJSON(&body)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if body.Rules == nil {
		body.Rules = []PolicyRule{}
	}
	for _, r := range body.Rules {
		if r.Operator == "$regex" {
			if _, err := regexp.Compile(r.Value); err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
		}
	}
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentVersionCollection)
	cv := &ComponentVersion{}
	err = coll.FindOne(c, bson.M{"_id": body.ComponentVersionID}).Decode(cv)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentPolicyCollection)
	res, err := coll.UpdateOne(c,
		bson.M{"component_version.component._id": cv.Component.ID},
		bson.M{"$setOnInsert": Policy{
			ComponentVersion: *cv,
			Type:             "release",
			CreateTime:       int(time.Now().Unix()),
			Creator:          c.GetString("user"),
			Rules:            body.Rules,
		}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		if res.UpsertedID == nil {
			common.CreateResponse(c, common.UnknownErrorCode, "create policy failed")
		} else {
			common.CreateResponse(c, common.SuccessCode, res.UpsertedID)
		}
	}
}

type DeletePolicyReqBody struct {
	ID primitive.ObjectID `json:"id" bson:"_id" binding:"required"`
}

func DeletePolicy(c *gin.Context) {
	body := DeletePolicyReqBody{}
	err := c.BindJSON(&body)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentPolicyCollection)
	res, err := coll.DeleteOne(c, body)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		common.CreateResponse(c, common.SuccessCode, res.DeletedCount)
	}
}

type DescribeComponentVersionListReqBody struct {
	ComponentID primitive.ObjectID `json:"component_id" bson:"component_id" binding:"required"`
}

func DescribeComponentVersionList(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	body := DescribeComponentVersionListReqBody{}
	err = c.BindJSON(&body)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   bson.M{"component._id": body.ComponentID},
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	coll := infra.MongoClient.Database(infra.MongoDatabase).
		Collection(infra.ComponentVersionCollection, options.Collection().
			SetReadPreference(readpref.Primary()))
	var data []ComponentVersion
	resp, err := common.DBSearchPaginate(coll, preq, func(cursor *mongo.Cursor) error {
		cv := ComponentVersion{}
		err = cursor.Decode(&cv)
		if err == nil {
			data = append(data, cv)
			return nil
		} else {
			return err
		}
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type Criteria struct {
	Key   string `json:"key" bson:"key"`
	Value string `json:"value" bson:"value"`
}

func DescribeComponentCriteria(c *gin.Context) {
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentCollection)
	cursor, err := coll.Aggregate(c, bson.A{
		bson.M{
			"$project": bson.M{
				"_id":   0,
				"key":   "$_id",
				"value": "$name",
			},
		},
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var data []Criteria
	err = cursor.All(c, &data)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		common.CreateResponse(c, common.SuccessCode, data)
	}
}

type DescribeComponentVersionCriteriaReqQuery struct {
	ComponentID string `form:"component_id" bson:"component_id" binding:"required"`
}

func DescribeComponentVersionCriteria(c *gin.Context) {
	query := DescribeComponentVersionCriteriaReqQuery{}
	err := c.BindQuery(&query)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	id, _ := primitive.ObjectIDFromHex(query.ComponentID)
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentVersionCollection)
	cursor, err := coll.Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"component._id": id,
			},
		},
		bson.M{
			"$project": bson.M{
				"_id":   0,
				"key":   "$_id",
				"value": "$version",
			},
		},
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var data []Criteria
	err = cursor.All(c, &data)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		common.CreateResponse(c, common.SuccessCode, data)
	}
}
