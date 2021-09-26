package biz

import (
	v0 "github.com/bytedance/Elkeid/server/manager/biz/hander/v0"
	v1 "github.com/bytedance/Elkeid/server/manager/biz/hander/v1"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/gin-gonic/gin"
)

func RegisterRouter(r *gin.Engine) {
	var (
		apiv0Group *gin.RouterGroup
		apiv1Group *gin.RouterGroup
	)

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

		userRouter := apiv1Group.Group("/user")
		{
			userRouter.POST("/login", v1.Login)
			userRouter.GET("/logout", v1.Logout)
			userRouter.POST("/createUser", v1.CreateUser)
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

			agentRouter.GET("/getTask/:id", v1.GetTaskByID)
			agentRouter.GET("/getJob/:id", v1.GetJobByID)

			agentRouter.POST("/updateSubTask", v1.UpdateSubTask)          //数据对账
			agentRouter.POST("/getSubTask/filter", v1.GetSubTaskByFilter) //任务查询
			agentRouter.GET("/getSubTask/:id", v1.GetSubTaskByID)         //任务查询
		}

		//The tag api is used to manage the agent as a group
		{
			apiv1Group.POST("/addTags", v1.AddTags)
			apiv1Group.POST("/addTags/filter", v1.AddTagsByFilter)

			apiv1Group.POST("/delTags", v1.RemoveTags)

			apiv1Group.GET("/getTags", v1.GetTags)
			apiv1Group.POST("/getTags", v1.GetTagsByID)
		}

		kubeSecRouter := apiv1Group.Group("/kubesec")
		{
			kubeSecRouter.GET("/clusters/authorized", v1.ProxyK8sRequest)
			kubeSecRouter.POST("/clusters/kubeconfig/:clusterName", v1.ProxyK8sRequest)

			kubeSecRouter.GET("/clusters/workerload/policies/:clusterName", v1.ProxyK8sRequest)
			kubeSecRouter.POST("/clusters/workerload/policies/:clusterName", v1.ProxyK8sRequest)

			kubeSecRouter.GET("/clusters/workerload/report/:clusterName", v1.ProxyK8sRequest)
			kubeSecRouter.POST("/clusters/workerload/report/:clusterName/:nameSpaceName", v1.ProxyK8sRequest)

			kubeSecRouter.GET("/clusters/workerload/checkinterval/:clusterName", v1.ProxyK8sRequest)
			kubeSecRouter.POST("/clusters/workerload/checkinterval/:clusterName", v1.ProxyK8sRequest)

			kubeSecRouter.GET("/clusters/workerload/filters/:clusterName", v1.ProxyK8sRequest)
			kubeSecRouter.POST("/clusters/workerload/filters/:clusterName", v1.ProxyK8sRequest)

		}
	}
}
