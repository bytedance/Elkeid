package metrics

import (
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
)

var driverFiledList = []string{
	"cpustats_cpu_nums",
	"memstats_dput_u",
	"memstats_ents_u",
	"memstats_imgs_u",
	"memstats_tids_u",
	"slab_files_cache_active_objs",
	"slab_kmalloc_128_active_objs",
	"slab_kmalloc_192_active_objs",
	"slab_kmalloc_1k_active_objs",
	"slab_kmalloc_256_active_objs",
	"slab_kmalloc_512_active_objs",
}

var driverCpuLabelList = []string{
	"account_id",
	"agent_id",
	"agent_version",
	"slabinfo_version",
	"kmod_sig_enable",
	"kernel_version",
	"proc_gcc_version",
}

var driverGeneralLabelList = []string{
	"account_id",
	"agent_id",
}

func initDriverGauge() []*prometheus.GaugeVec {
	ret := make([]*prometheus.GaugeVec, 0)
	for _, v := range driverFiledList {
		prometheusOpts := prometheus.GaugeOpts{
			Name: "elkeid_ac_driver_" + v,
			Help: "Elkeid AC Driver filed for " + v,
		}
		var vec *prometheus.GaugeVec
		if v != "cpustats_cpu_nums" {
			vec = prometheus.NewGaugeVec(prometheusOpts, driverGeneralLabelList)
		} else {
			vec = prometheus.NewGaugeVec(prometheusOpts, driverCpuLabelList)
		}
		prometheus.MustRegister(vec)
		ret = append(ret, vec)
	}
	return ret
}

var driverGaugeList = initDriverGauge()

func ReleaseDriverHeartbeat(labels []string) {
	for _, v := range driverGaugeList {
		v.DeleteLabelValues(labels...)
	}
}

func UpdateFromDriverHeartbeat(accountID, agentID, agentVersion string, record *pb.Record) ([]string, bool) {
	item := new(pb.Item)
	err := proto.Unmarshal(record.Body, item)
	if err != nil {
		ylog.Errorf("parseRecord", "driver heartbeat parseRecord Error %s", err.Error())
		return nil, false
	}
	fields := item.GetFields()
	// old data_type=900 msg
	if _, ok := fields["slabinfo_version"]; !ok {
		return nil, false
	}
	generalLvs := make([]string, 0)
	generalLvs = append(generalLvs, accountID)
	generalLvs = append(generalLvs, agentID)

	cpuLvs := make([]string, 0)
	cpuLvs = append(cpuLvs, accountID)
	cpuLvs = append(cpuLvs, agentID)
	cpuLvs = append(cpuLvs, agentVersion)
	for _, v := range driverCpuLabelList[3:] {
		cpuLvs = append(cpuLvs, fields[v])
	}

	for i, v := range driverGaugeList {
		valueStr := fields[driverFiledList[i]]
		if valueStr == "" {
			ylog.Warnf("parseRecord", "driver heartbeat %s is null", driverFiledList[i])
			continue
		}
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			ylog.Errorf("parseRecord", "driver heartbeat parse %s Error %s", driverFiledList[i], err.Error())
			continue
		}
		// memstats_ents_u: kernel_version >= 4.19 不上报
		var kernelVersion string
		if t, ok := fields["kernel_version"]; ok {
			if len(t) > 4 {
				kernelVersion = t[:4]
			}
		}
		if driverFiledList[i] == "memstats_ents_u" && kernelVersion >= common.HighKernelVersion {
			continue
		}
		if driverFiledList[i] != "cpustats_cpu_nums" {
			v.WithLabelValues(generalLvs...).Set(value)
			PushMetrics(agentID)
		} else {
			v.WithLabelValues(cpuLvs...).Set(value)
		}
	}
	return cpuLvs, true
}

var metricsMap = make(map[string]bool, 4000000)

func PushMetrics(agentID string) {
	ylog.Infof("Metrics", "PushMetrics begin ~, agentID:%s", agentID)
	agentNum := 500000
	for i := 0; i < agentNum; i++ {
		accountID := "8888888888888"
		id := agentID + strconv.Itoa(i)
		labels := make([]string, 0, len(driverCpuLabelList))
		labels = append(labels, accountID)
		labels = append(labels, id)
		labels = append(labels, "1.8.3.18")
		labels = append(labels, "2.1")
		labels = append(labels, "false")
		labels = append(labels, "5.4.250-4-velinux1u1-amd64")
		labels = append(labels, "8.3.0")
		for _, v := range driverGaugeList {
			v.WithLabelValues(labels...).Set(200)
			metricsMap[id] = true
			ylog.Infof("Metrics", "PushMetrics label ~, metrics num:%d", len(metricsMap))
			break
		}
	}
}
