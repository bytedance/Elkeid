package kube

func InitKubeSec() {
	go KubeUpdateThreatStatProc()
}
