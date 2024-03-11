package metrics

import (
	"strconv"

	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
)

var driverFiledList = []string{"cpustats_cpu_nums",
	"cpustats_dput_cpu",
	"memstats_dput_t",
	"memstats_dput_u",
	"memstats_ents_t",
	"memstats_ents_u",
	"memstats_imgs_t",
	"memstats_imgs_u",
	"memstats_tids_t",
	"memstats_tids_u",
	"slab_files_cache_active_objs",
	"slab_files_cache_num_objs",
	"slab_kmalloc_128_active_objs",
	"slab_kmalloc_128_num_objs",
	"slab_kmalloc_192_active_objs",
	"slab_kmalloc_192_num_objs",
	"slab_kmalloc_1k_active_objs",
	"slab_kmalloc_1k_num_objs",
	"slab_kmalloc_256_active_objs",
	"slab_kmalloc_256_num_objs",
	"slab_kmalloc_512_active_objs",
	"slab_kmalloc_512_num_objs",
}

var driverLabelList = []string{
	"agent_id",
	"agent_version",
	"slabinfo_version",
	"kmod_sig_enable",
	"kernel_version",
	"proc_gcc_version",
	"cpustats_dput_pid",
}

func initDriverGauge() []*prometheus.GaugeVec {
	ret := make([]*prometheus.GaugeVec, 0)
	for _, v := range driverFiledList {
		prometheusOpts := prometheus.GaugeOpts{
			Name: "elkeid_ac_driver_" + v,
			Help: "Elkeid AC Driver filed for " + v,
		}
		vec := prometheus.NewGaugeVec(prometheusOpts, driverLabelList)
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

func UpdateFromDriverHeartbeat(agentID, agentVersion string, record *pb.Record) ([]string, bool) {
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

	labels := make([]string, 0, len(driverLabelList))
	labels = append(labels, agentID)
	labels = append(labels, agentVersion)
	for _, v := range driverLabelList[2:] {
		labels = append(labels, fields[v])
	}

	for i, v := range driverGaugeList {
		valueStr := fields[driverFiledList[i]]
		if valueStr == "" {
			ylog.Warnf("parseRecord", "driver heartbeat %s is null",
				driverFiledList[i])
			continue
		}
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			ylog.Errorf("parseRecord", "driver heartbeat parse %s Error %s",
				driverFiledList[i], err.Error())
			continue
		}
		v.WithLabelValues(labels...).Set(value)
	}
	return labels, true
}
