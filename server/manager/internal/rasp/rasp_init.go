package rasp

func RaspInit() {
	go ChangeRaspMethodDB()
	go RaspConfigCronJob() // rasp配置缓存
	go RaspTaskCronJob()   // rasp任务下发
	go RaspSync("crontab") // rasp漏洞定期同步
}
