package kube

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type KubeThreatSourceIpStatistics struct {
	PublicNum  int `json:"public_ip_num,omitempty"`
	PrivateNum int `json:"private_ip_num,omitempty"`
	OtherNum   int `json:"other_ip_num,omitempty"`
}

type KubeThreatPreviewDataItem struct {
	Name       string  `json:"name,omitempty" bson:"name,omitempty"`
	Percentage float64 `json:"percentage,omitempty" bson:"percentage,omitempty"`
	Quantity   int32   `json:"quantity,omitempty" bson:"quantity,omitempty"`
}

type KubeThreatSourceDataItem struct {
	SourceIP string `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
}

type KubeThreatStatistics struct {
	ClusterId    string                      `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	SourceDist   []KubeThreatPreviewDataItem `json:"source_distribution,omitempty" bson:"source_distribution,omitempty"`
	ThreatDist   []KubeThreatPreviewDataItem `json:"threat_distribution,omitempty" bson:"threat_distribution,omitempty"`
	AbnormalDist []KubeThreatPreviewDataItem `json:"abnormal_distribution,omitempty" bson:"abnormal_distribution,omitempty"`
	ResourceDist []KubeThreatPreviewDataItem `json:"threatres_distribution,omitempty" bson:"threatres_distribution,omitempty"`
	ExploitDist  []KubeThreatPreviewDataItem `json:"vul_exploit_distribution" bson:"vul_exploit_distribution"`
	UpdateTime   string                      `json:"update_time,omitempty" bson:"update_time,omitempty"`
}

func parseCidr(network string, comment string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		panic(fmt.Sprintf("error parsing %s (%s): %s", network, comment, err))
	}
	return *ipNet
}

var (
	// Private CIDRs to ignore
	privateNetworks = []net.IPNet{
		// RFC1918
		// 10.0.0.0/8
		{
			IP:   []byte{10, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// 172.16.0.0/12
		{
			IP:   []byte{172, 16, 0, 0},
			Mask: []byte{255, 240, 0, 0},
		},
		// 192.168.0.0/16
		{
			IP:   []byte{192, 168, 0, 0},
			Mask: []byte{255, 255, 0, 0},
		},
		// RFC5735
		// 127.0.0.0/8
		{
			IP:   []byte{127, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// RFC1122 Section 3.2.1.3
		// 0.0.0.0/8
		{
			IP:   []byte{0, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// RFC3927
		// 169.254.0.0/16
		{
			IP:   []byte{169, 254, 0, 0},
			Mask: []byte{255, 255, 0, 0},
		},
		// RFC 5736
		// 192.0.0.0/24
		{
			IP:   []byte{192, 0, 0, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 5737
		// 192.0.2.0/24
		{
			IP:   []byte{192, 0, 2, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// 198.51.100.0/24
		{
			IP:   []byte{198, 51, 100, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// 203.0.113.0/24
		{
			IP:   []byte{203, 0, 113, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 3068
		// 192.88.99.0/24
		{
			IP:   []byte{192, 88, 99, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 2544
		// 192.18.0.0/15
		{
			IP:   []byte{192, 18, 0, 0},
			Mask: []byte{255, 254, 0, 0},
		},
		// RFC 3171
		// 224.0.0.0/4
		{
			IP:   []byte{224, 0, 0, 0},
			Mask: []byte{240, 0, 0, 0},
		},
		// RFC 1112
		// 240.0.0.0/4
		{
			IP:   []byte{240, 0, 0, 0},
			Mask: []byte{240, 0, 0, 0},
		},
		// RFC 919 Section 7
		// 255.255.255.255/32
		{
			IP:   []byte{255, 255, 255, 255},
			Mask: []byte{255, 255, 255, 255},
		},
		// RFC 6598
		// 100.64.0.0./10
		{
			IP:   []byte{100, 64, 0, 0},
			Mask: []byte{255, 192, 0, 0},
		},
	}
	// Sourced from https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	// where Global, Source, or Destination is False
	privateV6Networks = []net.IPNet{
		parseCidr("::/128", "RFC 4291: Unspecified Address"),
		parseCidr("::1/128", "RFC 4291: Loopback Address"),
		parseCidr("::ffff:0:0/96", "RFC 4291: IPv4-mapped Address"),
		parseCidr("100::/64", "RFC 6666: Discard Address Block"),
		parseCidr("2001::/23", "RFC 2928: IETF Protocol Assignments"),
		parseCidr("2001:2::/48", "RFC 5180: Benchmarking"),
		parseCidr("2001:db8::/32", "RFC 3849: Documentation"),
		parseCidr("2001::/32", "RFC 4380: TEREDO"),
		parseCidr("fc00::/7", "RFC 4193: Unique-Local"),
		parseCidr("fe80::/10", "RFC 4291: Section 2.5.6 Link-Scoped Unicast"),
		parseCidr("ff00::/8", "RFC 4291: Section 2.7"),
		// We disable validations to IPs under the 6to4 anycase prefix because
		// there's too much risk of a malicious actor advertising the prefix and
		// answering validations for a 6to4 host they do not control.
		// https://community.letsencrypt.org/t/problems-validating-ipv6-against-host-running-6to4/18312/9
		parseCidr("2002::/16", "RFC 7526: 6to4 anycast prefix deprecated"),
	}
)

func isPrivateV4(ip net.IP) bool {
	for _, ipNet := range privateNetworks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateV6(ip net.IP) bool {
	for _, ipNet := range privateV6Networks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func parseKubeSourceIp(ip string, info *KubeThreatSourceIpStatistics) {
	if info == nil {
		return
	}

	tmpIp := net.ParseIP(ip)
	if tmpIp == nil {
		info.OtherNum += 1
		return
	}

	if tmpIp.To4() != nil {
		if isPrivateV4(tmpIp) {
			info.PrivateNum += 1
		} else {
			info.PublicNum += 1
		}
	} else {
		if isPrivateV6(tmpIp) {
			info.PrivateNum += 1
		} else {
			info.PublicNum += 1
		}
	}
}

func KubeAggresRuleNameInfos(ctx context.Context, name string, query bson.D) (int, []KubeThreatPreviewDataItem) {
	var retData = make([]KubeThreatPreviewDataItem, 0)
	var retTotal = 0

	groupJs := bson.D{primitive.E{Key: "$group", Value: bson.D{
		primitive.E{Key: "_id", Value: "$rule_name"},
		primitive.E{Key: "quantity", Value: bson.D{
			primitive.E{Key: "$sum", Value: 1},
		}},
	}}}

	// abnormal behavior
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(name)
	totalNum, err := col.CountDocuments(ctx, query)
	if err != nil {
		ylog.Errorf("rule name aggress", "%s CountDocuments error %s", name, err.Error())
		return retTotal, retData
	}

	queryVulJs := bson.D{primitive.E{Key: "$match", Value: query}}
	projectJs := bson.D{
		primitive.E{Key: "$project", Value: bson.D{
			primitive.E{Key: "name", Value: "$_id"},
			primitive.E{Key: "quantity", Value: 1},
			primitive.E{Key: "percentage", Value: bson.D{
				primitive.E{Key: "$multiply", Value: bson.A{
					bson.D{primitive.E{Key: "$divide", Value: bson.A{
						"$quantity", totalNum}}}, 100,
				}},
			}},
		}}}
	queryPipe := mongo.Pipeline{queryVulJs, groupJs, projectJs}
	cur, err := col.Aggregate(ctx, queryPipe)
	if err != nil {
		ylog.Errorf("rule name aggress", "%s Aggregate error %s", name, err.Error())
		return retTotal, retData
	}

	var tmpResults []KubeThreatPreviewDataItem
	err = cur.All(ctx, &tmpResults)
	if err != nil {
		ylog.Errorf("rule name aggress", "%s decode error %s", name, err.Error())
	} else {
		retData = append(retData, tmpResults...)
	}

	retTotal = int(totalNum)
	_ = cur.Close(ctx)
	return retTotal, retData
}

func KubeQuerySourceInfos(ctx context.Context, name string, query bson.D) []KubeThreatSourceDataItem {
	var retList = make([]KubeThreatSourceDataItem, 0)

	srcQueryOption := options.Find().SetProjection(bson.D{
		primitive.E{Key: "_id", Value: 0},
		primitive.E{Key: "source_ip", Value: 1},
	})

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(name)
	cur, err := col.Find(ctx, query, srcQueryOption)
	if err != nil {
		ylog.Errorf("find resource ip", "%s query error %s", name, err.Error())
		return retList
	}

	var res []KubeThreatSourceDataItem
	err = cur.All(ctx, &res)
	if err != nil {
		ylog.Errorf("decode resource ip", "decode error %s", err.Error())
	} else {
		retList = append(retList, res...)
	}

	_ = cur.Close(ctx)
	return retList
}

func KubeUpdateClusterThreatStat(ctx context.Context, cluster_id *string) {
	baseQuery := bson.D{}
	vulQueryContent := bson.D{
		primitive.E{Key: "rule_name",
			// Value: bson.D{primitive.E{Key: "$in", Value: KubeVulExploitClassList}}},
			Value: bson.D{primitive.E{Key: "$regex", Value: "疑似"}}},
		primitive.E{Key: "__hit_wl", Value: false},
	}
	updateQuery := bson.D{
		primitive.E{Key: "cluster_id", Value: ""},
	}

	if cluster_id != nil {
		baseQuery = bson.D{
			primitive.E{Key: "cluster_id", Value: *cluster_id},
		}

		vulQueryContent = bson.D{
			primitive.E{Key: "cluster_id", Value: *cluster_id},
			primitive.E{Key: "rule_name",
				// Value: bson.D{primitive.E{Key: "$in", Value: KubeVulExploitClassList}}},
				Value: bson.D{primitive.E{Key: "$regex", Value: "疑似"}}},
			primitive.E{Key: "__hit_wl", Value: false},
		}
		updateQuery = bson.D{
			primitive.E{Key: "cluster_id", Value: *cluster_id},
		}
	}

	var info = KubeThreatStatistics{
		ClusterId:    "",
		SourceDist:   make([]KubeThreatPreviewDataItem, 0, 3),
		ThreatDist:   make([]KubeThreatPreviewDataItem, 0, 3),
		AbnormalDist: make([]KubeThreatPreviewDataItem, 0, 50),
		ResourceDist: make([]KubeThreatPreviewDataItem, 0, 50),
		ExploitDist:  make([]KubeThreatPreviewDataItem, 0, 50),
		UpdateTime:   time.Now().Format("2006-01-02 15:04:05"),
	}
	var srcInfo KubeThreatSourceIpStatistics

	abSrcList := KubeQuerySourceInfos(ctx, infra.KubeAbnormalBehaviorCollectionV1, baseQuery)
	abTotalNum, abRuleInfos := KubeAggresRuleNameInfos(ctx, infra.KubeAbnormalBehaviorCollectionV1, baseQuery)
	tcSrcList := KubeQuerySourceInfos(ctx, infra.KubeThreatResourceCreatV1, baseQuery)
	tcTotalNum, tcRuleInfos := KubeAggresRuleNameInfos(ctx, infra.KubeThreatResourceCreatV1, baseQuery)
	vuSrcList := KubeQuerySourceInfos(ctx, infra.KubeThreatResourceCreatV1, vulQueryContent)
	vuTotalNum, vuRuleInfos := KubeAggresRuleNameInfos(ctx, infra.KubeAlarmCollectionV1, vulQueryContent)

	// combine result
	totalNum := abTotalNum + tcTotalNum + vuTotalNum
	abPercent := float64(100*abTotalNum) / float64(totalNum)
	tcPercent := float64(100*tcTotalNum) / float64(totalNum)
	vuPercent := float64(100*vuTotalNum) / float64(totalNum)

	if len(abRuleInfos) > 0 {
		info.AbnormalDist = make([]KubeThreatPreviewDataItem, len(abRuleInfos))
		copy(info.AbnormalDist, abRuleInfos)
	}

	if abTotalNum > 0 {
		info.ThreatDist = append(info.ThreatDist, KubeThreatPreviewDataItem{
			Name:       "异常行为",
			Percentage: abPercent,
			Quantity:   int32(abTotalNum),
		})
	}

	for _, one := range abSrcList {
		parseKubeSourceIp(one.SourceIP, &srcInfo)
	}

	if len(tcRuleInfos) > 0 {
		info.ResourceDist = make([]KubeThreatPreviewDataItem, len(tcRuleInfos))
		copy(info.ResourceDist, tcRuleInfos)
	}

	if tcTotalNum > 0 {
		info.ThreatDist = append(info.ThreatDist, KubeThreatPreviewDataItem{
			Name:       "威胁资源",
			Percentage: tcPercent,
			Quantity:   int32(tcTotalNum),
		})
	}

	for _, two := range tcSrcList {
		parseKubeSourceIp(two.SourceIP, &srcInfo)
	}

	if len(vuRuleInfos) > 0 {
		info.ExploitDist = make([]KubeThreatPreviewDataItem, len(vuRuleInfos))
		copy(info.ExploitDist, vuRuleInfos)
	}

	if vuTotalNum > 0 {
		info.ThreatDist = append(info.ThreatDist, KubeThreatPreviewDataItem{
			Name:       "漏洞利用行为",
			Percentage: vuPercent,
			Quantity:   int32(vuTotalNum),
		})
	}

	for _, thr := range vuSrcList {
		parseKubeSourceIp(thr.SourceIP, &srcInfo)
	}

	// update info
	srcTotalNum := srcInfo.PublicNum + srcInfo.PrivateNum + srcInfo.OtherNum
	if srcInfo.PublicNum > 0 {
		tmpPerc := float64(srcInfo.PublicNum*100) / float64(srcTotalNum)
		info.SourceDist = append(info.SourceDist, KubeThreatPreviewDataItem{
			Name:       "公网",
			Percentage: tmpPerc,
			Quantity:   int32(srcInfo.PublicNum),
		})
	}

	if srcInfo.PrivateNum > 0 {
		tmpPerc := float64(srcInfo.PrivateNum*100) / float64(srcTotalNum)
		info.SourceDist = append(info.SourceDist, KubeThreatPreviewDataItem{
			Name:       "私网",
			Percentage: tmpPerc,
			Quantity:   int32(srcInfo.PrivateNum),
		})
	}

	if srcInfo.OtherNum > 0 {
		tmpPerc := float64(srcInfo.OtherNum*100) / float64(srcTotalNum)
		info.SourceDist = append(info.SourceDist, KubeThreatPreviewDataItem{
			Name:       "其他",
			Percentage: tmpPerc,
			Quantity:   int32(srcInfo.OtherNum),
		})
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeThreatStatisticsV1)
	updataOptions := options.UpdateOptions{}
	tmpOpt := updataOptions.SetUpsert(true)

	_, err := col.UpdateOne(ctx, updateQuery, bson.M{"$set": info}, tmpOpt)
	if err != nil {
		ylog.Errorf("update threat statics", err.Error())
	}
}

func KubeUpdateThreatStatProc() {
	for {
		runCtx := context.TODO()
		var allCluters []KubeClusterInfoSimpleItem
		clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
		ctCur, err := clusterCol.Find(runCtx, bson.M{})
		if err != nil {
			ylog.Errorf("HidsEventStatProc get cluster info error", err.Error())
		} else {
			err = ctCur.All(runCtx, &allCluters)
			if err != nil {
				ylog.Errorf("HidsEventStatProc decode cluster info error", err.Error())
			} else {
				for _, one := range allCluters {
					KubeUpdateClusterThreatStat(runCtx, &one.ClusterId)
				}
			}
			_ = ctCur.Close(runCtx)
		}

		// total stat
		KubeUpdateClusterThreatStat(runCtx, nil)

		// wait 1 min
		time.Sleep(60 * time.Second)
	}
}
