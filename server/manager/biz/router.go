package biz

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/bytedance/Elkeid/server/manager/static"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	v0 "github.com/bytedance/Elkeid/server/manager/biz/handler/v0"
	v1 "github.com/bytedance/Elkeid/server/manager/biz/handler/v1"
	v6 "github.com/bytedance/Elkeid/server/manager/biz/handler/v6"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/gin-gonic/gin"
)

var (
	Version string
	Commit  string
	Build   string
	CI      string
)

func registerForFrontEnd(r *gin.Engine) {
	indexHandler := func(ctx *gin.Context) {
		fullPath := ctx.Request.URL.Path
		fileName := ""
		fileType := ""
		if strings.HasSuffix(fullPath, ".ttf") {
			fileName = "fonts/" + strings.Split(fullPath, "/")[len(strings.Split(fullPath, "/"))-1]
			fileType = "ttf"
		} else if strings.HasSuffix(fullPath, ".js") ||
			strings.HasSuffix(fullPath, ".css") ||
			strings.HasSuffix(fullPath, ".png") ||
			strings.HasSuffix(fullPath, ".svg") ||
			strings.HasSuffix(fullPath, ".ico") ||
			strings.HasSuffix(fullPath, ".ttf") {
			fileName = strings.Split(fullPath, "/")[len(strings.Split(fullPath, "/"))-1]
			fileType = strings.Split(fullPath, ".")[len(strings.Split(fullPath, "."))-1]
		} else {
			ctx.Header("Content-Type", "text/html")
			ret, err := static.FrontendFile.ReadFile("frontend/index.html")
			if err != nil {
				_, _ = ctx.Writer.Write([]byte(err.Error()))
				return
			} else {
				ctx.Header("Content-Length", fmt.Sprint(len(ret)))
				_, _ = ctx.Writer.Write(ret)
			}
		}
		switch fileType {
		case "js":
			ctx.Header("Content-Type", "application/javascript")
		case "css":
			ctx.Header("Content-Type", "text/css")
		case "png":
			ctx.Header("Content-Type", "image/png")
		case "svg":
			ctx.Header("Content-Type", "image/svg")
		case "ico":
			ctx.Header("Content-Type", "image/x-icon")
		case "ttf":
			ctx.Header("Content-Type", "font/ttf")

		}
		ctx.Header("Content-Description", "File Transfer")
		ctx.Header("Content-Transfer-Encoding", "binary")
		ctx.Header("Content-Disposition", "attachment; filename="+fileName)
		ctx.FileFromFS(path.Join("frontend", fileName), http.FS(static.FrontendFile))
		return
	}

	r.GET("/", indexHandler)
	r.GET("/index.html", indexHandler)
	r.GET("/user/login", indexHandler)
	r.GET("/abnormal-list", indexHandler)
	r.GET("/alarm-detail", indexHandler)
	r.GET("/alarm-list", indexHandler)
	r.GET("/asset-fingerprint", indexHandler)
	r.GET("/backup-configure", indexHandler)
	r.GET("/backup-syslog", indexHandler)
	r.GET("/baseline", indexHandler)
	r.GET("/baseline-detail", indexHandler)
	r.GET("/basic-configure", indexHandler)
	r.GET("/comp-detail", indexHandler)
	r.GET("/comp-list", indexHandler)
	r.GET("/comp-policy", indexHandler)
	r.GET("/create-task", indexHandler)
	r.GET("/event-detail", indexHandler)
	r.GET("/event-list", indexHandler)
	r.GET("/exposure", indexHandler)
	r.GET("/file-box", indexHandler)
	r.GET("/file-download", indexHandler)
	r.GET("/host-detail", indexHandler)
	r.GET("/host-list", indexHandler)
	r.GET("/host-monitor", indexHandler)
	r.GET("/install-guide", indexHandler)
	r.GET("/kube", indexHandler)
	r.GET("/kube-alarm-detail", indexHandler)
	r.GET("/kube-alarm-list", indexHandler)
	r.GET("/kube-baseline", indexHandler)
	r.GET("/kube-baseline-detail", indexHandler)
	r.GET("/kube-config", indexHandler)
	r.GET("/kube-detail", indexHandler)
	r.GET("/kube-event-detail", indexHandler)
	r.GET("/kube-event-list", indexHandler)
	r.GET("/kube-whitelist", indexHandler)
	r.GET("/license", indexHandler)
	r.GET("/log-query", indexHandler)
	r.GET("/notify-mgmt", indexHandler)
	r.GET("/overview", indexHandler)
	r.GET("/rasp-alarm-detail", indexHandler)
	r.GET("/rasp-alarm-list", indexHandler)
	r.GET("/rasp-config", indexHandler)
	r.GET("/rasp-event-detail", indexHandler)
	r.GET("/rasp-event-list", indexHandler)
	r.GET("/rasp-list", indexHandler)
	r.GET("/rasp-vuln", indexHandler)
	r.GET("/rasp-white-list", indexHandler)
	r.GET("/service-alert", indexHandler)
	r.GET("/service-monitor", indexHandler)
	r.GET("/task-detail", indexHandler)
	r.GET("/task-list", indexHandler)
	r.GET("/threat-overview", indexHandler)
	r.GET("/threatres-list", indexHandler)
	r.GET("/user", indexHandler)
	r.GET("/virus-alarm-list", indexHandler)
	r.GET("/virus-task-detail", indexHandler)
	r.GET("/virus-white-list", indexHandler)
	r.GET("/vuln-list", indexHandler)
	r.GET("/white-list", indexHandler)
	r.NoRoute(indexHandler)
}

func RegisterRouter(r *gin.Engine) {
	r.GET("/metrics", func(c *gin.Context) {
		promhttp.Handler().ServeHTTP(c.Writer, c.Request)
	})

	registerForFrontEnd(r)

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"commit":  Commit,
			"build":   Build,
			"version": Version,
			"ci":      CI,
		})
	})

	r.Use(midware.Metrics())

	var (
		apiv0Group *gin.RouterGroup
		apiv1Group *gin.RouterGroup
		apiv6Group *gin.RouterGroup
	)
	r.Use(Cors())
	apiv0Group = r.Group("/api/v0")
	{
		//for cluster
		innerGroup := apiv0Group.Group("/inner")
		innerGroup.Use(midware.AKSKAuth())
		{
			innerGroup.POST("/sync", v0.Sync)
		}

		//for task check
		jobGroup := apiv0Group.Group("/job")
		jobGroup.Use(midware.TokenAuth())
		{
			jobGroup.POST("/new", v0.NewJob)
			jobGroup.POST("/distribute", v0.Distribute)
			jobGroup.POST("/stop", v0.Stop)
			jobGroup.GET("/stat", v0.Stat)
			jobGroup.GET("/result", v0.Result)
		}
	}

	apiv1Group = r.Group("/api/v1")
	{
		apiv1Group.Use(midware.TokenAuth())
		apiv1Group.Use(midware.RBACAuth())

		userRouter := apiv1Group.Group("/user")
		{
			userRouter.POST("/login", v1.UserLogin)
			userRouter.GET("/logout", v1.UserLoginout)
			userRouter.POST("/del", v1.DelUser)
			userRouter.GET("/info", v1.UserInfo)
			userRouter.POST("/update", v1.UpdateUser)
			userRouter.POST("/resetPassword", v1.ResetPassword)
			userRouter.POST("/checkUser", v1.CheckPassword)
		}

		agentRouter := apiv1Group.Group("/agent")
		{
			agentRouter.GET("/getStatus", v1.GetStatus)
			agentRouter.GET("/getStatus/:id", v1.GetStatusByID)
			agentRouter.POST("/getStatus/filter", v1.GetStatusByFilter)

			agentRouter.GET("/getConfig/:id", v1.GetConfigByID)

			agentRouter.GET("/getDefaultConfig", v1.GetDefaultConfig)
			agentRouter.POST("/updateDefaultConfig", v1.UpdateDefaultConfig)

			/*
				Agent Task
			*/
			agentRouter.POST("/createTask/ctrl", v1.CreateCtrlTask)
			agentRouter.POST("/createTask/config", v1.CreateConfTask)
			agentRouter.POST("/createTask/task", v1.CreateTaskTask)
			agentRouter.POST("/createTask/delConfig", v1.CreateDelConfTask)

			agentRouter.POST("/controlTask", v1.ControlAgentTask)

			agentRouter.POST("/quickTask/task", v1.QuickTaskTask)
			agentRouter.POST("/getTask/filter", v1.GetTaskByFilter)
			agentRouter.GET("/getTask/:id", v1.GetTaskByID)
			agentRouter.GET("/getJob/:id", v1.GetJobByID)

			//update subTask /subTask/filter
			agentRouter.POST("/updateSubTask", v1.UpdateSubTask)          //数据对账
			agentRouter.POST("/getSubTask/filter", v1.GetSubTaskByFilter) //任务查询
			agentRouter.GET("/getSubTask/:id", v1.GetSubTaskByID)         //任务查询

			//
			agentRouter.POST("/queryInfo", v1.QueryInfo) //server used
		}

		//The tag api is used to manage the agent as a group
		{
			apiv1Group.POST("/addTags", v1.AddTags)
			apiv1Group.POST("/addTags/filter", v1.AddTagsByFilter)

			apiv1Group.POST("/delTags", v1.RemoveTags)

			apiv1Group.GET("/getTags", v1.GetTags)
			apiv1Group.POST("/getTags", v1.GetTagsByID)
		}
	}

	// v6 group
	// console 面向前端版本
	apiv6Group = r.Group("/api/v6")
	{
		apiv6Group.Use(midware.TokenAuth())
		apiv6Group.Use(midware.RBACAuth())

		// 部分用户相关操作保留在v1上更改
		userRouter := apiv6Group.Group("/user")
		{
			userRouter.POST("/DelList", v6.DelUserList)
			userRouter.POST("/List", v6.GetUserList)
			userRouter.POST("/new", v1.CreateUserV6)
			userRouter.POST("/otp/status", v6.GetUserOTPStatus)
		}

		// 任务相关接口
		agentRouter := apiv6Group.Group("/agent")
		{
			agentRouter.GET("/getTask/:id", v6.GetTaskByID)
			agentRouter.POST("/controlTask", v1.ControlAgentTaskByNum)
			agentRouter.POST("/createAgentTask", v6.ControlAgent)
			agentRouter.POST("/getTaskList", v6.GetTaskList)
			agentRouter.POST("/getSubTaskList", v6.GetSubTaskList)
			agentRouter.POST("/GetErrorHostNum", v6.GetErrorHostNum)
			//agentRouter.POST("/PushAntiRansomStat", v6.PushAntiRansomStat)
		}
		assetCenter := apiv6Group.Group("/asset-center")
		{
			assetCenter.POST("/add", v1.NewAsset)
			assetCenter.POST("/bulkAdd", v1.BulkNewAsset)
			assetCenter.POST("/DescribeHosts", v6.DescribeHosts)
			assetCenter.GET("/DescribeHostDetail", v6.DescribeHostDetail)
			assetCenter.POST("/AddTags", v6.AddTags)
			assetCenter.POST("/UpdateTags", v6.UpdateTags)
			assetCenter.POST("/DeleteTags", v6.DeleteTags)
			assetCenter.GET("/DescribeTags", v6.DescribeTags)
			assetCenter.GET("/DescribePlatform", v6.DescribePlatform)
			assetCenter.GET("/DescribeIDC", v6.DescribeIDC)
			assetCenter.GET("/DescribeKernelVersion", v6.DescribeKernelVersion)
			assetCenter.GET("/DescribeHostStatistics", v6.DescribeHostStatistics)
			assetCenter.POST("/ExportHosts", v6.ExportHosts)
			//
			fingerprint := assetCenter.Group("/fingerprint")
			{
				fingerprint.POST("/DescribePort", v6.DescribePort)
				fingerprint.POST("/DescribeProcess", v6.DescribeProcess)
				fingerprint.POST("/DescribeUser", v6.DescribeUser)
				fingerprint.POST("/DescribeCron", v6.DescribeCron)
				fingerprint.POST("/DescribeService", v6.DescribeService)
				fingerprint.POST("/DescribeSoftware", v6.DescribeSoftware)
				fingerprint.POST("/DescribeIntegrity", v6.DescribeIntegrity)
				fingerprint.POST("/DescribeVolume", v6.DescribeVolume)
				fingerprint.POST("/DescribeNetInterface", v6.DescribeNetInterface)
				fingerprint.POST("/DescribeKmod", v6.DescribeKmod)
				fingerprint.POST("/ExportData", v6.ExportData)
				fingerprint.POST("/RefreshData", v6.RefreshData)
				fingerprint.GET("/DescribeRefreshStatus", v6.DescribeRefreshStatus)
				fingerprint.GET("/DescribeStatistics", v6.DescribeStatistics)
				fingerprint.GET("/DescribeTop5", v6.DescribeTop5)
				fingerprint.GET("/DescribeContainerStateStatistics", v6.DescribeContainerStateStatistics)
				fingerprint.POST("/DescribeContainer", v6.DescribeContainer)
				fingerprint.GET("/DescribeContainerDetail", v6.DescribeContainerDetail)
				fingerprint.GET("/DescribeAppGroup", v6.DescribeAppGroup)
				fingerprint.POST("/DescribeApp", v6.DescribeApp)
			}
		}

		shared := apiv6Group.Group("/shared")
		{
			shared.GET("/Download/:FileName", v6.Download)
			shared.POST("/Upload", v6.Upload) //上传文件
		}
		componentRouter := apiv6Group.Group("/component")
		{
			componentRouter.POST("/CreateComponent", v6.CreateComponent)
			componentRouter.POST("/DescribeComponentList", v6.DescribeComponentList)
			componentRouter.GET("/DescribeComponent", v6.DescribeComponent)
			componentRouter.GET("/DescribeRecommendComponentVersion", v6.DescribeRecommendComponentVersion)
			componentRouter.POST("/DescribeComponentVersionList", v6.DescribeComponentVersionList)
			componentRouter.POST("/PublishComponentVersion", v6.PublishComponentVersion)
			componentRouter.POST("/DescribePolicyList", v6.DescribePolicyList)
			componentRouter.POST("/CreatePolicy", v6.CreatePolicy)
			componentRouter.POST("/DeletePolicy", v6.DeletePolicy)
			componentRouter.GET("/DescribeComponentCriteria", v6.DescribeComponentCriteria)
			componentRouter.GET("/DescribeComponentVersionCriteria", v6.DescribeComponentVersionCriteria)
			// inner api
			componentRouter.POST("/GetComponentInstances", v6.GetComponentInstances) //server uesd

			componentRouter.POST("/CreateSyncConfigTask", v6.CreateSyncConfigTask)
			componentRouter.POST("/CreateRebootAgentTask", v6.CreateRebootAgentTask)
		}
		// 告警新接口
		alarmRouter := apiv6Group.Group("/alarm")
		{
			alarmRouter.POST("/update", v6.UpdateAlarmStatusManyForHids)
			alarmRouter.POST("/list", v6.GetAlarmListForHids)
			alarmRouter.GET("/statistics", v6.GetAlarmStatForHids)
			alarmRouter.POST("/add", v6.AddOneAlarm)
			alarmRouter.POST("/filterbywhite", v6.GetAlarmFilterByWhiteForHids)
			alarmRouter.POST("/export", v6.ExportAlarmListDataForHids)
			alarmRouter.GET("/query/:aid", v6.GetAlarmSummaryInfoForHids)
		}

		// 告警白名单
		alarmWhiteRouter := apiv6Group.Group("/whitelist")
		{
			alarmWhiteRouter.POST("/listing", v6.GetWhiteListWithCombineForHids)
			alarmWhiteRouter.POST("/increase", v6.MultiAddWhiteListWithCombineForHids)
			alarmWhiteRouter.POST("/del", v6.MultiDelWhiteListForHids)
			alarmWhiteRouter.POST("/update", v6.WhiteListUpdateOneForHids)
		}

		// 漏洞相关接口
		vulnRouter := apiv6Group.Group("/vuln")
		{
			vulnRouter.POST("/SendPkgList", v6.GetAgentPkgList)
			vulnRouter.POST("/Statistics", v6.GetVulnStatistics)
			vulnRouter.POST("/GetVulnList", v6.GetVulnList)
			vulnRouter.POST("/GetVulnInfo", v6.GetVulnInfo)
			vulnRouter.POST("/VulnHostList", v6.VulnHostList)
			vulnRouter.POST("/VulnIpControl", v6.VulnIpControl)
			vulnRouter.POST("/OneIpVulnControl", v6.OneIpVulnControl)
			vulnRouter.POST("/VulnControl", v6.VulnControl)
			vulnRouter.POST("/VulnControlNew", v6.VulnControlNew)
			vulnRouter.POST("/Download", v6.DownloadVulnData)
			vulnRouter.POST("/Detect", v6.VulnDetect)
			vulnRouter.GET("/VulnCheckStatus", v6.VulnCheckStatus)
			vulnRouter.POST("/DetectProgressDetail", v6.VulnDetectProgressDetail)
			vulnRouter.POST("/GetHostVulnInfo", v6.GetHostVulnInfo)
			vulnRouter.POST("/DownloadVulnList", v6.DownloadVulnList)
		}

		// 基线接口
		baselineRouter := apiv6Group.Group("/baseline")
		{
			baselineRouter.POST("/SendWeakPassData", v6.SendWeakPassData)
			baselineRouter.POST("/SendBaselineData", v6.SendBaselineData)
			baselineRouter.GET("/GetGroupList", v6.GetGroupList)
			baselineRouter.POST("/Detect", v6.Detect)
			baselineRouter.GET("/GroupStatistics", v6.GroupStatistics)
			baselineRouter.GET("/GroupCheckStatus", v6.GroupCheckStatus)
			baselineRouter.POST("/DetectProgressDetail", v6.DetectProgressDetail)
			baselineRouter.POST("/GetBaselineList", v6.GetBaselineList)
			baselineRouter.POST("/GetBaselineDetailList", v6.GetBaselineDetailList)
			baselineRouter.POST("/GetCheckResList", v6.GetCheckResList)
			baselineRouter.POST("/GetChecklistDetail", v6.GetChecklistDetail)
			baselineRouter.POST("/GetWhiteHostNum", v6.GetWhiteHostNum)
			baselineRouter.POST("/ChecklistWhiten", v6.ChecklistWhiten)
			baselineRouter.POST("/Statistics", v6.GetBaselineStatistics)
			baselineRouter.POST("/Download", v6.GetBaselineDownload)
			baselineRouter.POST("/GetBaselineCheckList", v6.GetBaselineCheckList)
			baselineRouter.POST("/GetCheckHostList", v6.GetCheckHostList)

		}
		// 系统告警
		systemRouter := apiv6Group.Group("/systemRouter")
		{
			systemRouter.POST("/InsertAlert", v6.InsertAlert)
			systemRouter.GET("/DescribeAlerts", v6.DescribeAlerts)
		}

		// 确实KO自动下载
		apiv6Group.POST("/Agent/Driver/KoMissedMsg", v6.SendAgentDriverKoMissedMsg)

		// 监控
		monitorRouter := apiv6Group.Group("/monitor")
		{
			// 首页
			monitorRouter.GET("/ServiceStatus", v6.MonitorServiceStatus)

			monitorRouter.GET("/AlertStatistics", v6.AlertStatistics)
			monitorRouter.GET("/AlertList", v6.AlertList)
			monitorRouter.POST("/IgnoreAlerts", v6.IgnoreAlerts)
			monitorRouter.POST("/ResetAlerts", v6.ResetAlerts)
			monitorRouter.POST("/ExportAlert", v6.ExportAlerts)

			// Agent
			monitorRouter.GET("/AgentCpuMetrics", v6.MetricsForAgentCpu())
			monitorRouter.GET("/AgentNetMetrics", v6.MetricsForAgentNetwork())
			monitorRouter.GET("/AgentDiskMetrics", v6.MetricsForAgentDisk())
			monitorRouter.GET("/AgentDiskUsageMetrics", v6.MetricsForAgentDiskUsage())
			monitorRouter.GET("/AgentMemoryMetrics", v6.MetricsForAgentMemory())

			// Host
			monitorRouter.GET("/HostStatistics", v6.MonitorHostStatistics)
			monitorRouter.GET("/DescribeHosts", v6.MonitorDescribeHosts)
			monitorRouter.GET("/HostAllMetrics", v6.MonitorHostAllMetrics)
			monitorRouter.GET("/HostAvgMetrics", v6.MonitorHostAvgMetrics)
			monitorRouter.POST("/ExportHost", v6.MonitorExportHost)

			// Service
			monitorRouter.GET("/ServiceStatistics", v6.MonitorServiceStatistics)
			monitorRouter.GET("/ServiceList", v6.MonitorServiceList)
			monitorRouter.POST("/ExportService", v6.MonitorExportService)
		}

		// RASP接口
		raspRouter := apiv6Group.Group("/rasp")
		{
			raspRouter.POST("/NewConfig", v6.NewRaspConfig)
			raspRouter.POST("/EditConfig", v6.EditRaspConfig)
			raspRouter.POST("/DelConfig", v6.DelRaspConfig)
			raspRouter.POST("/GetConfigList", v6.GetRaspConfigList)
			raspRouter.POST("/GetRaspProcessList", v6.GetRaspProcessList)
			raspRouter.POST("/GetRaspProcessDetail", v6.GetRaspProcessDetail)
			raspRouter.GET("/GetRaspStatistics", v6.GetRaspStatistics)
			raspRouter.GET("/GetRaspMethodMap", v6.GetRaspMethodMap)

			// vuln
			raspRouter.POST("/StatisticsVuln", v6.GetRaspVulnStatistics)
			raspRouter.POST("/GetRaspVulnList", v6.GetRaspVulnList)
			raspRouter.POST("/RaspVulnProcessList", v6.RaspVulnProcessList)

			// alarm
			raspRouter.POST("/alarm/add", v6.RaspAddOneAlarm)
			raspRouter.POST("/alarm/list", v6.GetAlarmListForRasp)
			raspRouter.GET("/alarm/statistics", v6.GetRaspAlarmStat)
			raspRouter.POST("/alarm/update", v6.MultiUpdateRaspAlarmStatus)
			raspRouter.POST("/alarm/export", v6.ExportRaspAlarmListData)
			raspRouter.GET("/alarm/query/:aid", v6.GetAlarmSummaryInfoForRasp)
			raspRouter.POST("/alarm/filterbywhite", v6.GetAlarmFilterByWhiteForRasp)

			// white
			raspRouter.POST("/whitelist/listing", v6.GetWhiteListWithCombineForRasp)
			raspRouter.POST("/whitelist/increase", v6.MultiAddWhiteListWithCombineForRasp)
			raspRouter.POST("/whitelist/del", v6.MultiDelWhiteListForRasp)
			raspRouter.POST("/whitelist/update", v6.WhiteListUpdateOneForRasp)
		}
		// 容器安全相关接口
		kubeRouter := apiv6Group.Group("/kube")
		{
			// alarm
			kubeRouter.POST("/addonealarm", v6.KubeAddOneAlarm)
			kubeRouter.POST("/alarm/list", v6.KubeListAlarm)
			kubeRouter.GET("/alarm/statistics", v6.GetAlarmStatForKube)
			kubeRouter.POST("/alarm/update", v6.UpdateAlarmStatusManyForKube)
			kubeRouter.POST("/alarm/filterbywhite", v6.GetAlarmFilterByWhiteForKube)
			kubeRouter.POST("/alarm/export", v6.ExportKubeAlarmListData)
			kubeRouter.GET("/alarm/query/:aid", v6.GetAlarmSummaryInfoForKube)

			// whitelist
			kubeRouter.POST("/whitelist/listing", v6.GetWhiteListWithCombineForKube)
			kubeRouter.POST("/whitelist/increase", v6.MultiAddWhiteListWithCombineForKube)
			kubeRouter.POST("/whitelist/del", v6.MultiDelWhiteListForKube)
			kubeRouter.POST("/whitelist/update", v6.WhiteListUpdateOneForKube)

			// cluster
			kubeRouter.GET("/inner/cluster/list", v6.KubeInnerClusterList) //server used
			kubeRouter.GET("/inner/test/cert/new", v6.KubeInnerTestNewCert)

			kubeRouter.POST("/GetConfigList", v6.GetClusterConfigList)
			kubeRouter.POST("/AddConfig", v6.NewClusterConfig)
			kubeRouter.POST("/DelConfig", v6.DelClusterConfig)
			kubeRouter.POST("/RenameConfig", v6.RenameClusterConfig)
			kubeRouter.POST("/GetClusterList", v6.GetClusterList)
			kubeRouter.POST("/GetClusterInfo", v6.GetClusterInfo)
			kubeRouter.POST("/GetNodeList", v6.GetNodeList)
			kubeRouter.POST("/GetWorkerList", v6.GetWorkerList)
			kubeRouter.POST("/GetPodList", v6.GetPodList)
			kubeRouter.POST("/GetContainerList", v6.GetContainerList)
			kubeRouter.GET("/GetClusterNameFromId", v6.GetClusterNameFromId)

			kubeRouter.POST("/ClusterDownload", v6.ClusterDownload)
			kubeRouter.POST("/NodeDownload", v6.NodeDownload)
			kubeRouter.POST("/WorkerDownload", v6.WorkerDownload)
			kubeRouter.POST("/PodDownload", v6.PodDownload)
			kubeRouter.POST("/ContainerDownload", v6.ContainerDownload)
			kubeRouter.GET("/PolicyDownload", v6.PolicyDownload)
			kubeRouter.GET("/WebhookDownload", v6.WebhookDownload)
			kubeRouter.GET("/KubeCreateShDownload", v6.KubeCreateShDownload)

		}

		// 首页相关接口
		overviewRouter := apiv6Group.Group("/overview")
		{
			overviewRouter.GET("DescribeAsset", v6.DescribeAsset)
			overviewRouter.GET("DescribeAgent", v6.DescribeAgent)
			overviewRouter.GET("/alarm", v6.GetOverviewAlarmStat)
			overviewRouter.GET("/vulnRisk", v6.VulnRisk)
			overviewRouter.GET("/baselineRisk", v6.BaselineRisk)
			overviewRouter.GET("/agentRisk", v6.AgentRisk)
		}
		// 病毒查杀相关接口
		virusRouter := apiv6Group.Group("/virus")
		{
			// alarm
			virusRouter.POST("/alarm/list", v6.GetAlarmListForVirus)
			virusRouter.GET("/alarm/statistics", v6.GetAlarmStatForVirus)
			virusRouter.POST("/alarm/update", v6.UpdateAlarmStatusManyForVirus)
			virusRouter.POST("/alarm/export", v6.ExportAlarmListDataForVirus)
			virusRouter.POST("/alarm/filterbywhite", v6.GetAlarmFilterByWhiteForVirus)
			virusRouter.GET("/alarm/query/:aid", v6.GetAlarmSummaryInfoForVirus)
			virusRouter.POST("/whitelist/update", v6.WhiteListUpdateOneForVirus)

			// white
			virusRouter.POST("/whitelist/listing", v6.GetWhiteListWithCombineForVirus)
			virusRouter.POST("/whitelist/increase", v6.MultiAddWhiteListWithCombineForVirus)
			virusRouter.POST("/whitelist/del", v6.MultiDelWhiteListForVirus)

			// task
			virusRouter.POST("/task/create", v6.CreatFileScanTaskForVirus)
			virusRouter.POST("/task/list", v6.GetTaskListForVirus)
			virusRouter.POST("/task/subtask/list", v6.GetSubTaskListForVirus)
			virusRouter.GET("/task/get/:id", v6.GetVirusTaskByID)
			virusRouter.POST("/task/hosts", v6.GetTaskHostListForVirus)
			virusRouter.GET("/task/statistics", v6.GetTaskStatisticsForVirus)
		}
		// 通知管理相关接口
		noticeRouter := apiv6Group.Group("/notice")
		{
			noticeRouter.POST("/add", v6.AddOneNoticeConfig)
			noticeRouter.POST("/del", v6.DelOneNoticeConfig)
			noticeRouter.POST("/modify", v6.ModifyOneNoticeConfig)
			noticeRouter.POST("/list", v6.GetNoticeList)
			noticeRouter.POST("/switch", v6.ChangeOneNoticeRunConfig)
			noticeRouter.GET("/get/:id", v6.GetOneNoticeConfig)
			noticeRouter.GET("/plugin/list", v6.GetNoticePluginNameList)
		}

		// 授权相关接口
		licenseRouter := apiv6Group.Group("/license")
		{
			licenseRouter.GET("/info", v6.LicenseOverview)
			licenseRouter.GET("/detail", v6.LicenseDetail)
		}
	}
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")
		var headerKeys []string
		for k := range c.Request.Header {
			headerKeys = append(headerKeys, k)
		}
		headerStr := strings.Join(headerKeys, ", ")
		if headerStr != "" {
			headerStr = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s", headerStr)
		} else {
			headerStr = "access-control-allow-origin, access-control-allow-headers"
		}
		if origin != "" {

			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session,X_Requested_With,Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers,Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma,FooBar,Content-Disposition, token")
			c.Header("Access-Control-Max-Age", "172800")
			c.Header("Access-Control-Allow-Credentials", "false")
			c.Set("content-type", "application/json")
		}

		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "")
		}
		c.Next()
	}
}
