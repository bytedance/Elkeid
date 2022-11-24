package virus_detection

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

func virusDetectionCron() {
	for {
		tmpCtx := context.TODO()

		// update stat
		UpdateVirusTaskStatistics(tmpCtx)

		// update running task
		UpdateVirusRunningTaskStatus(tmpCtx)

		ylog.Debugf("one CheckVirusTaskStatus end", "")

		time.Sleep(60 * time.Second)
	}
}

func InitVirusDetection() {
	go virusDetectionCron()
}
