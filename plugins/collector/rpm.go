package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

type RPMPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release"`
}

func GetRPMPackage(rootfs string) (packages []RPMPackage, err error) {
	var database []byte
	var f *os.File
	f, err = os.Open(rootfs + "/var/lib/rpm/Packages")
	if err != nil {
		return
	}
	var fstat os.FileInfo
	fstat, err = f.Stat()
	if err != nil {
		return
	}
	if fstat.Size() > 1024*1024*30 {
		err = errors.New("Size exceeds")
	}
	database, err = io.ReadAll(f)
	if err != nil {
		return
	}
	if binary.LittleEndian.Uint32(database[12:16]) != 0x061561 || database[25] != 0x08 {
		err = fmt.Errorf("Error database format")
		return
	}
	pageSize := binary.LittleEndian.Uint32(database[20:24])
	if pageSize < 512 {
		err = fmt.Errorf("Error database format")
		return
	}
	lastPgno := binary.LittleEndian.Uint32(database[32:36])
	if uint32(len(database)) < lastPgno*pageSize {
		err = fmt.Errorf("Error database format")
		return
	}
	for i := uint32(1); i < lastPgno; i++ {
		page := database[i*pageSize : (i+1)*pageSize]
		entries := binary.LittleEndian.Uint16(page[20:22])
		if uint32(entries)*2 > pageSize {
			err = fmt.Errorf("Error database format")
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
					for true {
						dataPage := database[pgno*pageSize : (pgno+1)*pageSize]
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
					pkg := RPMPackage{}
					for i := 0; i < int(indexLength); i++ {
						dtype := binary.BigEndian.Uint32(index[i*16+4 : i*16+8])
						if dtype != 6 {
							continue
						}
						tag := binary.BigEndian.Uint32(index[i*16 : i*16+4])
						switch tag {
						case 1000:
							boffset := binary.BigEndian.Uint32(index[i*16+8 : i*16+12])
							var eoffset uint32
							if uint32(i) != indexLength-1 {
								eoffset = binary.BigEndian.Uint32(index[(i+1)*16+8 : (i+1)*16+12])
							} else {
								eoffset = dataLength
							}
							pkg.Name = string(bytes.Trim(data[boffset:eoffset], "\x00"))
						case 1001:
							boffset := binary.BigEndian.Uint32(index[i*16+8 : i*16+12])
							var eoffset uint32
							if uint32(i) != indexLength-1 {
								eoffset = binary.BigEndian.Uint32(index[(i+1)*16+8 : (i+1)*16+12])
							} else {
								eoffset = dataLength
							}
							pkg.Version = string(bytes.Trim(data[boffset:eoffset], "\x00"))
						case 1002:
							boffset := binary.BigEndian.Uint32(index[i*16+8 : i*16+12])
							var eoffset uint32
							if uint32(i) != indexLength-1 {
								eoffset = binary.BigEndian.Uint32(index[(i+1)*16+8 : (i+1)*16+12])
							} else {
								eoffset = dataLength
							}
							pkg.Release = string(bytes.Trim(data[boffset:eoffset], "\x00"))
						default:
							continue
						}
					}
					if pkg.Name != "" && pkg.Version != "" {
						packages = append(packages, pkg)
					}
				}
			}
		}
	}
	if len(packages) == 0 {
		err = errors.New("deb packages is empty")
	}
	return
}
