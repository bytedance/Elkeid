package baseline

func InitBaseline() {
	go SetBaselineCheckTask(0, "crontab")
	go judgeTaskTimeout("crontab_back")
	go judgeTaskTimeout("once")
	go calcuBaselineStatistic()
	go ChangeBaselineDB()
}
