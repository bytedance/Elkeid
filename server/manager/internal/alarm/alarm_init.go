package alarm

func InitAlarm() {
	go alarmPeriodicStatisticsWorker()

	go alarmAsyncUpdateWorker()
}
