package container

func ContainerInit() {
	go SetKubeData("crontab") // 定时计算生成漏洞列表
}
