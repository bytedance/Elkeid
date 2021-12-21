package biz

import (
	"fmt"
	"net/http"
	"strings"

	v0 "github.com/bytedance/Elkeid/server/manager/biz/hander/v0"
	v1 "github.com/bytedance/Elkeid/server/manager/biz/hander/v1"
	v6 "github.com/bytedance/Elkeid/server/manager/biz/hander/v6"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/gin-gonic/gin"
)

func RegisterRouter(r *gin.Engine) {
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

		//for control
		controlGroup := apiv0Group.Group("/control")
		controlGroup.Use(midware.TokenAuth())
		{
			controlGroup.POST("/setConnectionCount", v0.SetConnectionCount)
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
			// userRouter.POST("/createUser", v1.CreateUser)
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
			agentRouter.GET("/getCount", v1.GetCount)
			agentRouter.GET("/getVersion", v1.GetVersion)

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
		}

		// 任务相关接口
		agentRouter := apiv6Group.Group("/agent")
		{
			agentRouter.GET("/getTask/:id", v1.GetTaskByID)
			agentRouter.POST("/controlTask", v1.ControlAgentTaskByNum)
			agentRouter.POST("/createAgentTask", v6.ControlAgent)
			agentRouter.POST("/createPluTask", v6.ControlPlugin)
			agentRouter.POST("/getTaskList", v6.GetTaskList)
			agentRouter.POST("/getSubTaskList", v6.GetSubTaskList)
			agentRouter.POST("/GetErrorHostNum", v6.GetErrorHostNum)
		}
		assetCenter := apiv6Group.Group("/asset-center")
		{
			assetCenter.POST("/add", v1.NewAsset)
			assetCenter.POST("/DescribeHosts", v6.DescribeHosts)
			assetCenter.GET("/DescribeHostDetail", v6.DescribeHostDetail)
			assetCenter.POST("/AddTags", v6.AddTags)
			assetCenter.POST("/UpdateTags", v6.UpdateTags)
			assetCenter.POST("/DeleteTags", v6.DeleteTags)
			assetCenter.GET("/DescribeTags", v6.DescribeTags)
			assetCenter.GET("/DescribePlatform", v6.DescribePlatform)
			assetCenter.GET("/DescribeIDC", v6.DescribeIDC)
			assetCenter.GET("/DescribeHostStatistics", v6.DescribeHostStatistics)
			assetCenter.POST("/DescribeHostPort", v6.DescribeHostPort)
			assetCenter.POST("/DescribeHostProcess", v6.DescribeHostProcess)
			assetCenter.POST("/DescribeHostUser", v6.DescribeHostUser)
			assetCenter.POST("/DescribeHostService", v6.DescribeHostService)
			assetCenter.POST("/DescribeHostCron", v6.DescribeHostCron)
			assetCenter.POST("/DescribeHostSoftware", v6.DescribeHostSoftware)
			assetCenter.POST("/ExportHosts", v6.ExportHosts)
			assetCenter.GET("/DescribeHostPlatformStatistics", v6.DescribeHostPlatformStatistics)
			assetCenter.GET("/DescribeAgentVersionStatistics", v6.DescribeAgentVersionStatistics)
			assetCenter.GET("/DescribeTop10AlarmHosts", v6.DescribeTop10AlarmHosts)
			assetCenter.GET("/DescribeTop10VulnHosts", v6.DescribeTop10VulnHosts)
		}
		situation := apiv6Group.Group("/situation")
		{
			situation.GET("/DescribeLast7DaysAlarmStatistics", v6.DescribeLast7DaysAlarmStatistics)
			situation.GET("/DescribeLast7DaysVulnStatistics", v6.DescribeLast7DaysVulnStatistics)
			situation.GET("/DescribeLast7DaysOperationStatistics", v6.DescribeLast7DaysOperationStatistics)
		}
		shared := apiv6Group.Group("/shared")
		{
			shared.GET("/Download/:FileName", v6.Download)
		}
		// 组件相关接口
		moduleRouter := apiv6Group.Group("/module")
		{
			moduleRouter.POST("/CreateModule", v6.CreateModule)
			moduleRouter.POST("/GetModuleList", v6.GetModuleList)
			moduleRouter.POST("/DeleteModule", v6.DeleteModule)
			moduleRouter.POST("/UpdateModule", v6.UpdateModule)
			moduleRouter.POST("/GetModuleInfo", v6.GetModuleInfo)
			moduleRouter.POST("/GetModuleId", v6.GetModuleId)
		}

		// 漏洞相关接口
		vulnRouter := apiv6Group.Group("/vuln")
		{
			vulnRouter.POST("/SendPkgList", v6.GetAgentPkgList)
			vulnRouter.POST("/Statistics", v6.GetVulnStatistics)
			vulnRouter.POST("/GetVulnList", v6.GetVulnList)
			vulnRouter.GET("/GetVulnInfo", v6.GetVulnInfo)
			vulnRouter.POST("/VulnHostList", v6.VulnHostList)
			vulnRouter.POST("/VulnIpControl", v6.VulnIpControl)
			vulnRouter.POST("/OneIpVulnControl", v6.OneIpVulnControl)
			vulnRouter.POST("/VulnControl", v6.VulnControl)
			vulnRouter.POST("/FlushCpeCache", v6.FlushCpeCache)
		}

		// 告警新接口
		alarmRouter := apiv6Group.Group("/alarm")
		{
			alarmRouter.POST("/update", v6.UpdateAlarmStatus)
			alarmRouter.POST("/list", v6.GetAlarmList)
			alarmRouter.GET("/statistics", v6.GetAlarmStat)
			alarmRouter.GET("/get/:aid", v6.GetOneAlarm)
			alarmRouter.GET("/raw/:aid", v6.GetOneAlarmRaw)
			alarmRouter.POST("/add", v6.AddOneAlarm)
		}

		// 告警白名单
		alarmWhiteRouter := apiv6Group.Group("/whitelist")
		{
			alarmWhiteRouter.POST("/list", v6.GetWhiteList)
			alarmWhiteRouter.POST("/add", v6.WhiteListAddMulti)
			alarmWhiteRouter.POST("/del", v6.WhiteListDelMulti)
		}

		// 系统告警
		systemRouter := apiv6Group.Group("/systemRouter")
		{
			systemRouter.POST("/InsertAlert", v6.InsertAlert)
			systemRouter.GET("/DescribeAlerts", v6.DescribeAlerts)
		}
	}
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")
		var headerKeys []string
		for k, _ := range c.Request.Header {
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
