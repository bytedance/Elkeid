package kube

type KubeClusterInfoSimpleItem struct {
	ClusterId   string `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty" bson:"cluster,omitempty"`
	ClusterArea string `json:"cluster_area,omitempty" bson:"cluster_area,omitempty"`
}
