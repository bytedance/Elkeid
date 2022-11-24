package alarm

import (
	"errors"

	"github.com/bytedance/Elkeid/server/manager/infra"
)

func getAlarmCollectName(alarmType string) (string, error) {
	retName := ""

	switch alarmType {
	case AlarmTypeHids:
		retName = infra.HubAlarmCollectionV1
	case AlarmTypeRasp:
		retName = infra.RaspAlarmCollectionV1
	case AlarmTypeKube:
		retName = infra.KubeAlarmCollectionV1
	case AlarmTypeVirus:
		retName = infra.VirusDetectionCollectionV1
	default:
		typeErr := errors.New("unkown alarm type")
		return retName, typeErr
	}

	return retName, nil
}

func getWhiteCollectName(whitelistType string) (string, error) {
	retName := ""

	switch whitelistType {
	case AlarmTypeHids:
		retName = infra.HubWhiteListCollectionV1
	case AlarmTypeRasp:
		retName = infra.RaspAlarmWhiteV1
	case AlarmTypeKube:
		retName = infra.KubeAlarmWhiteCollectionV1
	case AlarmTypeVirus:
		retName = infra.VirusDetectionWhiteCollectionV1
	default:
		typeErr := errors.New("Unkown whitelist type")
		return retName, typeErr
	}

	return retName, nil
}

func getAlarmStatCollectionName(alarmType string) (string, error) {
	var retStr = ""

	switch alarmType {
	case AlarmTypeHids:
		retStr = infra.HidsAlarmStatCollectionV1
	case AlarmTypeRasp:
		retStr = infra.RaspAlarmStatCollectionV1
	case AlarmTypeKube:
		retStr = infra.KubeAlarmStatCollectionV1
	default:
		typeErr := errors.New("unkown event type for alarm stat")
		return retStr, typeErr
	}

	return retStr, nil
}
