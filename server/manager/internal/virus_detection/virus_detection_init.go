package virus_detection

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

func virusDetectionCron() {
	// update old running task
	UpdateVirusRunningTaskStatus(context.Background())

	for {
		tmpCtx := context.TODO()

		// update stat
		UpdateVirusTaskStatistics(tmpCtx)

		ylog.Debugf("one CheckVirusTaskStatus end", "")

		time.Sleep(60 * time.Second)
	}
}

func InitVirusDetection() {
	go virusDetectionCron()
}
