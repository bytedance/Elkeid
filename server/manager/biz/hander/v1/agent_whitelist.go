package v1

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type WhiteList struct {
	Type      int                    `json:"type" bson:"type"`
	Filter    []common.FilterContent `json:"filter" binding:"dive" bson:"filter"`
	Condition string                 `json:"condition" binding:"oneof=$and $or $nor" bson:"condition"`

	InsertTime int64 `json:"insert_time" bson:"insert_time"`
	UpdateTime int64 `json:"update_time" bson:"update_time"`
}

type WhiteListWithID struct {
	ID        primitive.ObjectID     `bson:"_id"`
	Type      int                    `bson:"type"`
	Filter    []common.FilterContent `bson:"filter"`
	Condition string                 `bson:"condition"`

	InsertTime int64 `bson:"insert_time"`
	UpdateTime int64 `bson:"update_time"`
}

type WLUpdater struct {
	Filter  bson.M
	Updater bson.M
}

type WhiteListWorker struct {
	wlChan chan *WLUpdater
}

func (w *WhiteListWorker) Init() {
	w.wlChan = make(chan *WLUpdater, 1024)
}

func (w *WhiteListWorker) Add(item *WLUpdater) {
	w.wlChan <- item
}

//TODO 索引优化，限定白名单key范围
func (w *WhiteListWorker) Run() {
	ylog.Infof("WhiteListWorker", "Run now!")

	go w.runChecker()
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	var item *WLUpdater
	for {
		select {
		case item = <-w.wlChan:
			ylog.Debugf("wlChan", "Filter:%v, Updater:%v", item.Filter, item.Updater)
			res, err := col.UpdateMany(context.Background(), item.Filter, item.Updater)
			if err != nil {
				ylog.Errorf("WhiteListWorker", "UpdateMany Error %s", err.Error())
			} else {
				ylog.Debugf("WhiteListWorker", "res.ModifiedCount %d, res.MatchedCount %d, res.UpsertedCount %d", res.ModifiedCount, res.MatchedCount, res.UpsertedCount)
			}
		}
	}
}

func (w *WhiteListWorker) runChecker() {
	ylog.Infof("WhiteListChecker", "Run now!")
	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	wlCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ticker.C:
			wls := make([]WhiteListWithID, 0, 0)
			cur, err := wlCol.Find(context.Background(), bson.M{})
			if err != nil {
				ylog.Errorf("WhiteListChecker", err.Error())
				continue
			}
			err = cur.All(context.Background(), &wls)
			if err != nil {
				ylog.Errorf("WhiteListChecker", err.Error())
				continue
			}

			updateTime := time.Now().Unix()
			for _, v := range wls {
				tmp := common.FilterQuery{Filter: v.Filter, Condition: v.Condition}
				filter := bson.M{"$and": bson.A{tmp.Transform(), bson.M{"__checked": false}}}

				test11, _ := json.Marshal(filter)
				ylog.Debugf("runChecker", "Filter:%s", string(test11))
				res, err := alarmCol.UpdateMany(context.Background(), filter,
					bson.M{"$set": bson.M{"__hit_wl": true}, "$addToSet": bson.M{"__wl": v.ID}})

				if err != nil {
					ylog.Errorf("WhiteListChecker", err.Error())
				} else {
					ylog.Debugf("WhiteListChecker", "res.ModifiedCount %d, res.MatchedCount %d, res.UpsertedCount %d", res.ModifiedCount, res.MatchedCount, res.UpsertedCount)
				}
			}

			//update
			_, err = alarmCol.UpdateMany(context.Background(), bson.M{"__update_time": bson.M{"$lt": updateTime}, "__checked": false},
				bson.M{"$set": bson.M{"__checked": true, "__update_time": time.Now().Unix()}})
		}
	}
}

var whiteListWorker WhiteListWorker

func init() {
	whiteListWorker.Init()
	go whiteListWorker.Run()
}

//新增白名单：1）写入白名单 2）更新告警字段
func NewWhiteList(c *gin.Context) {
	var item WhiteList
	err := c.BindJSON(&item)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	item.InsertTime = time.Now().Unix()
	item.UpdateTime = time.Now().Unix()
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
	iRes, err := col.InsertOne(c, item)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	filter := common.FilterQuery{Filter: item.Filter, Condition: item.Condition}
	tmp := &WLUpdater{
		Filter:  filter.Transform(),
		Updater: bson.M{"$set": bson.M{"__hit_wl": true, "__update_time": time.Now().Unix()}, "$addToSet": bson.M{"__wl": iRes.InsertedID}},
	}
	whiteListWorker.Add(tmp)
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func QueryWhiteLists(c *gin.Context) {
	var pageRequest common.PageRequest

	err := c.BindQuery(&pageRequest)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	filterQuery, err := common.BindFilterQuery(c)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
	pageOption := common.PageOption{Page: pageRequest.Page, PageSize: pageRequest.PageSize, Filter: filterQuery.Transform(), Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageOption.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}
	modelPage, err := common.DBModelPaginate(
		collection,
		pageOption,
		func(cursor *mongo.Cursor) (interface{}, error) {
			var item map[string]interface{}
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("QueryWhiteLists", err.Error())
				return nil, err
			}
			return item, nil
		})

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, modelPage)
}

type WLDeleter struct {
	IDList []string `json:"id_list"`
}

type WLDelResp struct {
	ID   string `json:"id" bson:"id"`
	Code int    `json:"code" bson:"code"`
	Msg  string `json:"msg" bson:"msg"`
}

//删除白名单：1）删除白名单 2）删除告警字段
func DelWhiteLists(c *gin.Context) {
	items := WLDeleter{}
	err := c.BindJSON(&items)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	res := make([]WLDelResp, 0, len(items.IDList))
	objList := make([]primitive.ObjectID, len(items.IDList))
	for _, v := range items.IDList {
		tmp := WLDelResp{
			ID:   v,
			Code: 0,
			Msg:  "ok",
		}

		objId, err := primitive.ObjectIDFromHex(v)
		if err != nil {
			tmp.Code = 1
			tmp.Msg = err.Error()
		} else {
			objList = append(objList, objId)
		}
		res = append(res, tmp)
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)
	_, err = col.DeleteMany(c, bson.M{"_id": bson.M{"$in": objList}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	//异步将告警从白名单去除
	for _, v := range objList {
		tmp1 := &WLUpdater{
			Filter:  bson.M{"__wl": bson.M{"$size": 1}, "__wl.0": v},
			Updater: bson.M{"$set": bson.M{"__hit_wl": false, "__update_time": time.Now().Unix()}},
		}
		whiteListWorker.Add(tmp1)

		tmp2 := &WLUpdater{
			Filter:  bson.M{},
			Updater: bson.M{"$pull": bson.M{"__wl": v}},
		}
		whiteListWorker.Add(tmp2)
	}

	common.CreateResponse(c, common.SuccessCode, res)
}

// add for other packet to call
func InotifyWhiteWorker(item *WLUpdater) {
	whiteListWorker.Add(item)
}
