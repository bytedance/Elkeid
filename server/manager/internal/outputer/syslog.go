package outputer

import (
	"encoding/json"
	"errors"
	"log/syslog"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

type SyslogWorker struct {
	log_handler  *syslog.Writer
	level_map    map[string]int
	msg_type     string
	log_addr     string
	log_fac      int
	log_protocol string
	Queue        chan *DataModel
}

const (
	SYSLOG_ALARM_LEVEL_CRITICAL string = "critical"
	SYSLOG_ALARM_LEVEL_HIGH     string = "high"
	SYSLOG_ALARM_LEVEL_MEDIUM   string = "medium"
	SYSLOG_ALARM_LEVEL_LOW      string = "low"
)

func InitSyslogConnect(conf *NoticeMsgConfigSyslog) (*syslog.Writer, error) {
	if conf == nil {
		return nil, errors.New("empty config for InitSyslogConnect")
	}

	syslogFac := syslog.Priority(conf.Facility)
	logHandler, err := syslog.Dial(conf.Protocol, conf.SyslogServer, syslogFac|syslog.LOG_INFO, "CWPP")
	if err != nil {
		return nil, err
	}

	return logHandler, nil
}

func (b *SyslogWorker) Init(conf *OutputerConfig) error {
	var err error

	if conf == nil {
		return errors.New("empty config for SyslogWorker")
	}

	if conf.MsgConfig.Syslog == nil {
		return errors.New("empty config for SyslogWorker")
	}

	if conf.Type == "" {
		return errors.New("empty type for HubPluginWorker")
	}

	b.msg_type = conf.Type
	b.level_map = make(map[string]int)
	for _, one := range conf.LevelList {
		b.level_map[one] = 1
	}

	b.log_handler, err = InitSyslogConnect(conf.MsgConfig.Syslog)
	if err != nil {
		ylog.Errorf("init connect to syslog failure", err.Error())
		// return err
	}

	// set the config
	b.log_addr = conf.MsgConfig.Syslog.SyslogServer
	b.log_protocol = conf.MsgConfig.Syslog.Protocol
	b.log_fac = conf.MsgConfig.Syslog.Facility

	// init channel
	b.Queue = make(chan *DataModel, ConfigOutputerQueueMax)

	// init coroutine
	go b.WaitForInputMsg()

	return nil
}

func (b *SyslogWorker) WaitForInputMsg() {
	for {
		if d, ok := <-b.Queue; ok {
			if d != nil {
				// data to string
				jsonByte, err := json.Marshal(d.Data)
				if err != nil {
					ylog.Errorf("syslogWorker decode error", err.Error())
					return
				}

				jsonStr := string(jsonByte)

				if b.log_handler == nil {
					// try to connect
					tmpConfig := &NoticeMsgConfigSyslog{
						SyslogServer: b.log_addr,
						Facility:     b.log_fac,
						Protocol:     b.log_protocol,
						Remarks:      "",
					}

					b.log_handler, err = InitSyslogConnect(tmpConfig)
					if err != nil {
						ylog.Errorf("connect to syslog for SendMsg failure", err.Error())
						// return err
						return
					}
				}

				// write data
				switch d.HitModel.Level {
				case SYSLOG_ALARM_LEVEL_CRITICAL:
					err = b.log_handler.Crit(jsonStr)
				case SYSLOG_ALARM_LEVEL_HIGH:
					err = b.log_handler.Err(jsonStr)
				case SYSLOG_ALARM_LEVEL_MEDIUM:
					err = b.log_handler.Warning(jsonStr)
				case SYSLOG_ALARM_LEVEL_LOW:
					err = b.log_handler.Notice(jsonStr)
				default:
					err = b.log_handler.Info(jsonStr)
				}

				if err != nil {
					ylog.Errorf("syslogWorker send log error", err.Error())
					return
				}
			}
		} else {
			ylog.Infof("stop syslog for", "%s", b.log_addr)
			return
		}
	}
}

func (b *SyslogWorker) HitModel(model DataHitModelInfo) bool {

	if model.Model == b.msg_type {
		if len(b.level_map) > 0 {
			_, ok := b.level_map[model.Level]
			if ok {
				return true
			}
		} else {
			return true
		}
	}

	return false
}

func (b *SyslogWorker) SendMsg(dm *DataModel) {
	if dm == nil {
		return
	}

	select {
	case b.Queue <- dm:
		return
	default:
		ylog.Errorf("channel blocked in SyslogWorker for", "%s", b.log_addr)
	}
}

func (b *SyslogWorker) Close() {
	err := b.log_handler.Close()
	if err != nil {
		ylog.Errorf("SyslogWorker", "Close %s %s, error %s", b.log_addr, b.log_protocol, err.Error())
	}
	// close the channel
	close(b.Queue)
	return
}
