package container

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type ClusterModuleStatus struct {
	Status    string `json:"status" bson:"status"`
	ErrReason string `json:"err_reason" bson:"err_reason"`
}
type ClusterConfig struct {
	ClusterId     string `json:"cluster_id" bson:"cluster_id"`
	ClusterName   string `json:"cluster_name" bson:"cluster_name"`
	ClusterRegion string `json:"cluster_region" bson:"cluster_region"`
	ClusterStatus string `json:"cluster_status" bson:"cluster_status"`
	CreateTime    int64  `json:"create_time" bson:"create_time"`
	KubeConfig    string `json:"kube_config" bson:"kube_config"`
	User          string `json:"user" bson:"user"`
	ErrReason     string `json:"err_reason" bson:"err_reason"`
	ModuleStatus  struct {
		Threat      string `json:"threat" bson:"threat"`
		Application string `json:"application" bson:"application"`
		Baseline    string `json:"baseline" bson:"baseline"`
		Exposure    string `json:"exposure" bson:"exposure"`
	} `json:"module_status" bson:"module_status"`
}
type ClusterInfo struct {
	ClusterId      string `json:"cluster_id" bson:"cluster_id"`
	ClusterName    string `json:"cluster_name" bson:"cluster_name"`
	ClusterRegion  string `json:"cluster_region" bson:"cluster_region"`
	ClusterVersion string `json:"cluster_version" bson:"cluster_version"`
	CreateTime     int64  `json:"create_time" bson:"create_time"`
	NodeNum        int64  `json:"node_num" bson:"node_num"`
	PodNum         int64  `json:"pod_num" bson:"pod_num"`
	WorkerNum      int64  `json:"worker_num" bson:"worker_num"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
	ModuleStatus   struct {
		Threat      ClusterModuleStatus `json:"threat" bson:"threat"`
		Application ClusterModuleStatus `json:"application" bson:"application"`
		Baseline    ClusterModuleStatus `json:"baseline" bson:"baseline"`
		Exposure    ClusterModuleStatus `json:"exposure" bson:"exposure"`
	} `json:"module_status" bson:"module_status"`
	Risk struct {
		Event struct {
			Critical int64 `json:"critical" bson:"critical"`
			High     int64 `json:"high" bson:"high"`
			Medium   int64 `json:"medium" bson:"medium"`
			Low      int64 `json:"low" bson:"low"`
			Total    int64 `json:"total" bson:"total"`
		} `json:"event" bson:"event"`
		Alarm struct {
			Critical int64 `json:"critical" bson:"critical"`
			High     int64 `json:"high" bson:"high"`
			Medium   int64 `json:"medium" bson:"medium"`
			Low      int64 `json:"low" bson:"low"`
			Total    int64 `json:"total" bson:"total"`
		} `json:"alarm" bson:"alarm"`
		Threat struct {
			VulnExploit        int64 `json:"vuln_exploit" bson:"vuln-exploit"`
			ErrorBehavior      int64 `json:"error_behavior" bson:"error_behavior"`
			ThreatSourceCreate int64 `json:"threat_source_create" bson:"threat-source-create"`
			Total              int64 `json:"total" bson:"total"`
		} `json:"threat" bson:"threat"`
	} `json:"risk" bson:"risk"`
}
type ClusterNodeInfo struct {
	ClusterId     string `json:"cluster_id" bson:"cluster_id"`
	ClusterName   string `json:"cluster_name" bson:"cluster_name"`
	ClusterRegion string `json:"cluster_region" bson:"cluster_region"`
	NodeId        string `json:"node_id" bson:"node_id"`
	NodeName      string `json:"node_name" bson:"node_name"`
	NodeStatus    string `json:"node_status" bson:"node_status"`
	NodeRole      string `json:"node_role" bson:"node_role"`
	NodeVersion   string `json:"node_version" bson:"node_version"`
	HostName      string `json:"host_name" bson:"host_name"`
	IntranetIp    string `json:"intranet_ip" bson:"intranet_ip"`
	ExtranetIp    string `json:"extranet_ip" bson:"extranet_ip"`
	SystemImage   string `json:"system_image" bson:"system_image"`
	KernelVersion string `json:"kernel_version" bson:"kernel_version"`
	Runtime       string `json:"runtime" bson:"runtime"`
	UpdateTime    int64  `json:"update_time" bson:"update_time"`
}
type ClusterWorkerInfo struct {
	ClusterId  string   `json:"cluster_id" bson:"cluster_id"`
	WorkerId   string   `json:"worker_id" bson:"worker_id"`
	WorkerName string   `json:"worker_name" bson:"worker_name"`
	WorkerType string   `json:"worker_type" bson:"worker_type"`
	Namespace  string   `json:"namespace" bson:"namespace"`
	UpdateTime int64    `json:"update_time" bson:"update_time"`
	PodList    []string `json:"pod_list" bson:"pod_list"`
	CreateTime int64    `json:"create_time" bson:"create_time"`
}
type ClusterPodInfo struct {
	ClusterId  string `json:"cluster_id" bson:"cluster_id"`
	PodId      string `json:"pod_id" bson:"pod_id"`
	PodName    string `json:"pod_name" bson:"pod_name"`
	Namespace  string `json:"namespace" bson:"namespace"`
	PodStatus  string `json:"pod_status" bson:"pod_status"`
	PodIp      string `json:"pod_ip" bson:"pod_ip"`
	NodeIp     string `json:"node_ip" bson:"node_ip"`
	NodeName   string `json:"node_name" bson:"node_name"`
	UpdateTime int64  `json:"update_time" bson:"update_time"`
	CreateTime int64  `json:"create_time" bson:"create_time"`
}
type ClusterContainerInfo struct {
	ClusterId     string `json:"cluster_id" bson:"cluster_id"`
	ContainerId   string `json:"container_id" bson:"container_id"`
	ContainerName string `json:"container_name" bson:"container_name"`
	UpdateTime    int64  `json:"update_time" bson:"update_time"`
	Image         string `json:"image" bson:"image"`
	PodId         string `json:"pod_id" bson:"pod_id"`
}

// ServiceInfo represents the service information.
type ServiceInfo struct {
	Namespace  string `json:"namespace"`            // namespace of the service
	Name       string `json:"name"`                 // name of the service
	Type       string `json:"type"`                 // type of the service
	ExternalIP string `json:"externalIP,omitempty"` // externalIPs of the service.
	Ports      string `json:"ports"`                // ports of the service

}

// IngressPathInfo represents the path information.
type IngressPathInfo struct {
	Path        string `json:"path" bson:"path"`                // path
	Service     string `json:"service" bson:"service"`          //service for the path
	ServiceName string `json:"serviceName" bson:"service_name"` //service for the path
	Port        string `json:"port" bson:"port"`                // port of the service
}

// IngressHostInfo represents the ingress host information.
type IngressHostInfo struct {
	Host     string            `json:"host,omitempty"`  // host domain
	TLS      bool              `json:"tls,omitempty"`   // is tls enabled
	PathInfo []IngressPathInfo `json:"paths,omitempty"` // path information
}

// IngressInfo represents the ingress information.
type IngressInfo struct {
	Namespace string            `json:"namespace"`       // namespace of the ingress
	Name      string            `json:"name,omitempty"`  // the ingress name
	IPs       []string          `json:"IPs,omitempty"`   // the ingress name
	HostInfo  []IngressHostInfo `json:"rules,omitempty"` // the ingress host information
}

// NodeInfo represents the node information.
type NodeInfo struct {
	Name       string `json:"name"`       // the node name
	ExternalIP string `json:"externalIP"` // the externalIPs of the node
}

// KubeExposedSubject represents exposed subject
type KubeExposedSubject struct {
	Kind           string   `json:"kind,omitempty"`      // kind of the workload, eg, deployment, pod, and so on
	NameSpace      string   `json:"namespace,omitempty"` // namespace of the workload
	Name           string   `json:"name,omitempty"`      // name of the workload
	HostPorts      []string `json:"hostPorts"`
	ServiceAccount string   `json:"serviceaccount,omitempty"` // the name of the serviceaccount for the workload
	ExternalIP     string   `json:"externalIP,omitempty"`
}

// KubeRolePermissions represent the permissions that the role and clusterrole have
type KubeRolePermissions struct {
	Privileged  bool     `json:"privileged"`
	Permissions []string `json:"permissions,omitempty"`
	NameSpace   string   `json:"namespace"` // namespace of the workload
}

// KubeRbacContent represents rbac role and clusterrole
type KubeRbacContent struct {
	Roles        map[string]KubeRolePermissions `json:"roles"`
	ClusterRoles map[string]KubeRolePermissions `json:"clusterroles"`
}

// KubeExposedContent stores the analysis content
type KubeExposedContent struct {
	Ingresses      *[]IngressInfo      `json:"ingresses,omitempty"`
	Services       *[]ServiceInfo      `json:"services,omitempty"`
	Nodes          *[]NodeInfo         `json:"nodes,omitempty"`
	ExposedSubject *KubeExposedSubject `json:"exposedSubject,omitempty"`
	RbacContent    *KubeRbacContent    `json:"RBAC,omitempty"`
}

// KubeExposedSurfaceResultData stores the analysis results
type KubeExposedSurfaceResultData struct {
	ExposedType    int                `json:"exposedType"`
	ExposedContent KubeExposedContent `json:"content,omitempty"`
}

// KubeExposedSurface is the Schema for the kubeexposedsurfaces API
type KubeExposedSurface struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta            `json:"metadata,omitempty"`
	Result          KubeExposedSurfaceResultData `json:"result,omitempty"`
}

// KubeExposedSurfaceList contains a list of KubeExposedSurface
type KubeExposedSurfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeExposedSurface `json:"items"`
}

type ContainerExposedData struct {
	ExposureId      string        `json:"exposure_id" bson:"exposure_id"`
	ContainerName   string        `json:"container_name" bson:"container_name"`
	ContainerType   string        `json:"container_type" bson:"container_type"`
	Namespace       string        `json:"namespace" bson:"namespace"`
	ExposureType    []string      `json:"exposure_type" bson:"exposure_type"`
	IfRbac          bool          `json:"if_rbac" bson:"if_rbac"`
	Name            string        `json:"name" bson:"name"`
	ContainerId     string        `json:"container_id" bson:"container_id"`
	Region          string        `json:"region" bson:"region"`
	RiskDescription string        `json:"risk_description" bson:"risk_description"`
	ExposedType     int           `json:"exposed_type" bson:"exposed_type"`
	NodeList        []ExposedNode `json:"node_list" bson:"node_list"`
	EdgeList        []ExposedEdge `json:"edge_list" bson:"edge_list"`
	UpdateTime      int64         `json:"update_time" bson:"update_time"`
	CreateTime      int64         `json:"create_time" bson:"create_time"`
	IfAlive         bool          `json:"if_alive" bson:"if_alive"`
}

type HostInfoType struct {
	Host     string            `json:"host" bson:"host"`
	Tls      string            `json:"tls" bson:"tls"`
	PathInfo []IngressPathInfo `json:"path_info" bson:"path_info"`
}
type ExposedNode struct {
	NodeId         string         `json:"node_id" bson:"node_id"`
	NodeType       string         `json:"node_type" bson:"node_type"`
	Name           string         `json:"name" bson:"name"`
	ExternalIp     string         `json:"external_ip" bson:"external_ip"`
	Namespace      string         `json:"namespace" bson:"namespace"`
	Type           string         `json:"type" bson:"type"`
	Ports          []string       `json:"ports" bson:"ports"`
	ServiceAccount string         `json:"service_account" bson:"service_account"`
	Service        string         `json:"service" bson:"service"`
	ServiceList    []string       `json:"service_list" bson:"service_list"`
	HostInfo       []HostInfoType `json:"host_info" bson:"host_info"`
	InternalIp     string         `json:"internal_ip" bson:"internal_ip"`
	Ips            []string       `json:"ips" bson:"ips"`
}
type ExposedEdge struct {
	Source   string `json:"source" bson:"source"`
	Target   string `json:"target" bson:"target"`
	IfDashed bool   `json:"if_dashed" bson:"if_dashed"`
}

const (
	ClusterStatusRunning = "running"

	ClusterStatusError       = "error"
	ClusterWorkerDaemonSet   = "DaemonSet"
	ClusterWorkerDeployment  = "Deployment"
	ClusterWorkerReplicaSet  = "ReplicaSet"
	ClusterWorkerStatefulSet = "StatefulSet"
	ClusterWorkerJob         = "Job"
	ClusterWorkerCronJob     = "CronJob"

	ClusterModuleInactive = "inactive"
)
