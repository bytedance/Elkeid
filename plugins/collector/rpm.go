package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/bytedance/plugins"
	"go.uber.org/zap"
)

const (
	HashMagicNumber      = 0x061561
	HashMetadataPageType = 0x08
	TAG_NAME             = 1000
	TAG_VERSION          = 1001
	TAG_RELEASE          = 1002
	TAG_EPOCH            = 1003
)

type Rpm struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release"`
}

func parseRpmList() (rpms []Rpm, err error) {
	rpms = []Rpm{}
	var f *os.File
	f, err = os.Open("/var/lib/rpm/Packages")
	if err != nil {
		return
	}
	defer f.Close()
	header := make([]byte, 36)
	_, err = f.ReadAt(header, 0)
	if err != nil {
		return
	}
	if binary.LittleEndian.Uint32(header[12:16]) != 0x061561 || header[25] != HashMetadataPageType {
		return
	}
	pageSize := binary.LittleEndian.Uint32(header[20:24])
	if pageSize < 512 {
		return
	}
	lastPgno := binary.LittleEndian.Uint32(header[32:36])
	s, err := f.Stat()
	if err != nil {
		return
	}
	if uint32(s.Size()) < lastPgno*pageSize {
		return
	}
	zap.S().Info("scanning rpm")
	for i := uint32(1); i < lastPgno; i++ {
		if len(rpms) >= MaxPackageNum {
			break
		}
		page := make([]byte, pageSize)
		_, err = f.ReadAt(page, int64(i*pageSize))
		if err != nil {
			break
		}
		entries := binary.LittleEndian.Uint16(page[20:22])
		if uint32(entries)*2 > pageSize {
			return
		}
		pageType := page[25]
		// 只看HashPage
		if pageType == 13 {
			// 只要value
			for j := uint16(1); j < entries; j += 2 {
				entryIndex := binary.LittleEndian.Uint16(page[26+(j*2) : 26+((j+1)*2)])
				entryType := page[entryIndex]
				// 只看OFFPAGE
				if entryType == 3 {
					pgno := binary.LittleEndian.Uint32(page[entryIndex+4 : entryIndex+8])
					tlen := binary.LittleEndian.Uint32(page[entryIndex+8 : entryIndex+12])
					buf := make([]byte, 0, tlen)
					for {
						dataPage := make([]byte, pageSize)
						_, err = f.ReadAt(dataPage, int64(pgno*pageSize))
						if err != nil {
							break
						}
						pgno = binary.LittleEndian.Uint32(dataPage[16:20])
						if pgno == 0 {
							hfOffset := binary.LittleEndian.Uint16(dataPage[22:24])
							buf = append(buf, dataPage[26:26+hfOffset]...)
							break
						} else {
							buf = append(buf, dataPage[26:]...)
						}
					}
					indexLength := binary.BigEndian.Uint32(buf[0:4])
					dataLength := binary.BigEndian.Uint32(buf[4:8])
					index := buf[8 : 8+indexLength*16]
					data := buf[8+indexLength*16:]
					rpm := Rpm{}
					for i := 0; i < int(indexLength); i++ {
						dtype := binary.BigEndian.Uint32(index[i*16+4 : i*16+8])
						if dtype != 6 {
							continue
						}
						tag := binary.BigEndian.Uint32(index[i*16 : i*16+4])
						switch tag {
						case TAG_NAME:
							boffset := binary.BigEndian.Uint32(index[i*16+8 : i*16+12])
							var eoffset uint32
							if uint32(i) != indexLength-1 {
								eoffset = binary.BigEndian.Uint32(index[(i+1)*16+8 : (i+1)*16+12])
							} else {
								eoffset = dataLength
							}
							rpm.Name = string(bytes.Trim(data[boffset:eoffset], "\x00"))
						case TAG_VERSION:
							boffset := binary.BigEndian.Uint32(index[i*16+8 : i*16+12])
							var eoffset uint32
							if uint32(i) != indexLength-1 {
								eoffset = binary.BigEndian.Uint32(index[(i+1)*16+8 : (i+1)*16+12])
							} else {
								eoffset = dataLength
							}
							rpm.Version = string(bytes.Trim(data[boffset:eoffset], "\x00"))
						case TAG_RELEASE:
							boffset := binary.BigEndian.Uint32(index[i*16+8 : i*16+12])
							var eoffset uint32
							if uint32(i) != indexLength-1 {
								eoffset = binary.BigEndian.Uint32(index[(i+1)*16+8 : (i+1)*16+12])
							} else {
								eoffset = dataLength
							}
							rpm.Release = string(bytes.Trim(data[boffset:eoffset], "\x00"))
						default:
							continue
						}
					}
					if rpm.Name != "" && rpm.Version != "" {
						rpms = append(rpms, rpm)
					}
				}
			}
		}
	}
	return
}
func GetRpm() {
	rpms, _ := parseRpmList()
	zap.S().Infof("scan rpm done, total: %v\n", len(rpms))
	data, _ := json.Marshal(rpms)
	rec := &plugins.Record{
		DataType:  5005,
		Timestamp: time.Now().Unix(),
		Data: &plugins.Payload{
			Fields: map[string]string{"data": string(data)},
		},
	}
	Client.SendRecord(rec)
}

func init() {
	go func() {
		rand.Seed(time.Now().UnixNano())
		time.Sleep(time.Second * time.Duration(rand.Intn(600)))
		GetRpm()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d %d * * *", rand.Intn(60), rand.Intn(6)), GetRpm)
		SchedulerMu.Unlock()
	}()
}
