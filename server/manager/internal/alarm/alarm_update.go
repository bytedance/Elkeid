package alarm

import (
	"context"
	"errors"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// variable
const (
	alarmStatusUpdateAsyncChannelCacheMax int = 100
)

var (
	alarmStatusUpdateAsyncChannel = make(chan UpdateAlarmStatusAsyncData, alarmStatusUpdateAsyncChannelCacheMax)
)

// data struct
type UpdateAlarmStatusAsyncData struct {
	AlarmType                    string `json:"alarm_type" bson:"alarm_type"`
	User                         string `json:"user" bson:"user"`
	UpdateTime                   int64  `json:"update_time" bson:"update_time"`
	AlarmStatusUpdateManyRequest `json:",inline" bson:",inline"`
}

type AlarmDataStructForUpdateStatusDecode struct {
	ID primitive.ObjectID `json:"_id" bson:"_id"`
}

// function
func doUpdateAlarmStatus(data *UpdateAlarmStatusAsyncData) {
	if data == nil {
		return
	}

	alarmCollectionName, err := getAlarmCollectName(data.AlarmType)
	if err != nil {
		ylog.Errorf("func UpdateAlarmStatusAsyncWorker get alarm collection name error",
			"alarm_type %s error %s", data.AlarmType, err.Error())
		return
	}

	runCtx := context.TODO()
	alarmIdList := make([]primitive.ObjectID, 0, 50)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmCollectionName)

	if data.AlarmIdList != nil {
		for _, one := range *data.AlarmIdList {
			objId, err := primitive.ObjectIDFromHex(one)
			if err != nil {
				ylog.Errorf("decode alarmId to objectId error", "alarmId %s error %s", one, err.Error())
			} else {
				alarmIdList = append(alarmIdList, objId)
			}
		}
	} else if data.Conditions != nil {
		alarmManyQueryCont := combineCommAlarmQueryCondision(data.Conditions, data.AlarmType, false)
		alarmManyQuery := bson.M{
			"$and": alarmManyQueryCont,
		}
		alarmManyCur, aErr := collection.Find(runCtx, alarmManyQuery)
		if aErr != nil {
			ylog.Errorf("doUpdateAlarmStatus find error", "condision %+v error %s", *data.Conditions, aErr.Error())
			return
		}

		var manayRes []AlarmDataStructForUpdateStatusDecode
		aErr = alarmManyCur.All(runCtx, &manayRes)
		if aErr != nil {
			ylog.Errorf("doUpdateAlarmStatus decode error", "error %s", aErr.Error())
			return
		}

		for _, one := range manayRes {
			alarmIdList = append(alarmIdList, one.ID)
		}
	} else {
		// nothing to do
		return
	}

	// update the status
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	bulkWrites := make([]mongo.WriteModel, 0, len(alarmIdList))
	updateJs := bson.M{"$set": bson.M{AdfnAlarmStatus: data.NewStatus,
		AdfnHandlerUser: data.User, AdfnUpdateTime: data.UpdateTime,
	}}
	for _, two := range alarmIdList {
		model := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"_id": two}).SetUpdate(updateJs).SetUpsert(false)
		bulkWrites = append(bulkWrites, model)
	}

	if len(bulkWrites) > 0 {
		_, err = collection.BulkWrite(runCtx, bulkWrites, writeOption)
		if err != nil {
			ylog.Errorf("bulk write for alarm status error", "num %d error %s", len(bulkWrites), err.Error())
			return
		}
	}
}

func updateAlarmEndpointHandleTimeout(ctx context.Context, alarmType string) error {
	alarmCollectionName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return err
	}

	nowTime := time.Now().Unix()
	//lastTime := nowTime - FileIsolationBoxTaskTimeoutMax
	lastTime := nowTime - 120
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmCollectionName)
	timeoutFilter := bson.M{AdfnAlarmStatus: AlarmStatusByEndpointProcessing, AdfnUpdateTime: bson.M{"$lt": lastTime}}
	timeoutUpdateContent := bson.M{"$set": bson.M{
		AdfnAlarmStatus: AlarmStatusHandleByEndpointFailure,
		AdfnUpdateTime:  nowTime,
		AdfnErrorReason: "time out",
	}}

	_, err = collection.UpdateMany(ctx, timeoutFilter, timeoutUpdateContent)
	if err != nil {
		return err
	}

	return nil
}

func checkAlarmEndpointHandle() {
	runCtx := context.TODO()

	// check hids
	err := updateAlarmEndpointHandleTimeout(runCtx, AlarmTypeHids)
	if err != nil {
		ylog.Errorf("checkAlarmEndpointHandle run updateAlarmEndpointHandleTimeout for hids error", err.Error())
	}

	// check rasp
	err = updateAlarmEndpointHandleTimeout(runCtx, AlarmTypeRasp)
	if err != nil {
		ylog.Errorf("checkAlarmEndpointHandle run updateAlarmEndpointHandleTimeout for rasp error", err.Error())
	}

	// check virus
	err = updateAlarmEndpointHandleTimeout(runCtx, AlarmTypeVirus)
	if err != nil {
		ylog.Errorf("checkAlarmEndpointHandle run updateAlarmEndpointHandleTimeout for virus error", err.Error())
	}
}

func alarmAsyncUpdateWorker() {
	checkTicker := time.NewTicker(1 * time.Minute)

	for {
		select {
		case inAlarmData, ok := <-alarmStatusUpdateAsyncChannel:
			if !ok {
				ylog.Errorf("alarmStatusUpdateAsyncChannel is close", "exit alarmAsyncUpdateWorker")
				return
			}

			doUpdateAlarmStatus(&inAlarmData)
		case <-checkTicker.C:
			checkAlarmEndpointHandle()
		}
	}
}

func UpdateAlarmStatus(alarmType string, user string, condition AlarmStatusUpdateManyRequest) error {
	_, err := getAlarmCollectName(alarmType)
	if err != nil {
		return err
	}

	asyncUpdateData := UpdateAlarmStatusAsyncData{
		AlarmType:                    alarmType,
		User:                         user,
		UpdateTime:                   time.Now().Unix(),
		AlarmStatusUpdateManyRequest: condition,
	}

	select {
	case alarmStatusUpdateAsyncChannel <- asyncUpdateData:
		ylog.Debugf("send alarm update data to async update chanel", "alarmType %s", alarmType)
		break
	default:
		return errors.New("async update channel is full")
	}

	return nil
}
