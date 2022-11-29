package rpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	HashMagicNumber            = 0x061561
	HashOffIndexPageType uint8 = 3
	OverflowPageType     uint8 = 7
	HashMetadataPageType uint8 = 8
	HashPageType         uint8 = 13
	IndexSize                  = 2
	HashOffPageSize            = 12
	HashPageHeaderSize         = 26

	RPM_INDEX_ENTRY_SIZE = 16
	// rpmTag_e
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
	RPMTAG_NAME           = 1000
	RPMTAG_VERSION        = 1001
	RPMTAG_RELEASE        = 1002
	RPMTAG_EPOCH          = 1003
	RPMTAG_ARCH           = 1022
	RPMTAG_SOURCERPM      = 1044
	RPMTAG_SIZE           = 1009
	RPMTAG_LICENSE        = 1014
	RPMTAG_VENDOR         = 1011
	RPMTAG_DIRINDEXES     = 1116
	RPMTAG_BASENAMES      = 1117
	RPMTAG_DIRNAMES       = 1118
	RPMTAG_FILEDIGESTS    = 1035
	RPMTAG_FILEDIGESTALGO = 5011

	// rpmTagType_e
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L431
	RPM_MIN_TYPE          = 0
	RPM_NULL_TYPE         = 0
	RPM_CHAR_TYPE         = 1
	RPM_INT8_TYPE         = 2
	RPM_INT16_TYPE        = 3
	RPM_INT32_TYPE        = 4
	RPM_INT64_TYPE        = 5
	RPM_STRING_TYPE       = 6
	RPM_BIN_TYPE          = 7
	RPM_STRING_ARRAY_TYPE = 8
	RPM_I18NSTRING_TYPE   = 9
	RPM_MAX_TYPE          = 9
)

type DigestAlgorithm int32

const (
	PGPHASHALGO_MD5         = iota + 1 /*!< MD5 */
	PGPHASHALGO_SHA1                   /*!< SHA1 */
	PGPHASHALGO_RIPEMD160              /*!< RIPEMD160 */
	_                                  /* Reserved for double-width SHA (experimental) */
	PGPHASHALGO_MD2                    /*!< MD2 */
	PGPHASHALGO_TIGER192               /*!< TIGER192 */
	PGPHASHALGO_HAVAL_5_160            /*!< HAVAL-5-160 */
	PGPHASHALGO_SHA256                 /*!< SHA256 */
	PGPHASHALGO_SHA384                 /*!< SHA384 */
	PGPHASHALGO_SHA512                 /*!< SHA512 */
	PGPHASHALGO_SHA224                 /*!< SHA224 */
)

func (d DigestAlgorithm) String() string {
	switch d {
	case 1:
		return "md5"
	case 2:
		return "sha1"
	case 3:
		return "ripemd160"
	case 5:
		return "md2"
	case 6:
		return "tiger192"
	case 7:
		return "haval-5-160"
	case 8:
		return "sha256"
	case 9:
		return "sha384"
	case 10:
		return "sha512"
	case 11:
		return "sha224"
	default:
		return "unknown-digest-algorithm"
	}
}

// source: https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L73
type GenericMetadataPageHeader struct {
	LSN           [8]byte  /* 00-07: LSN. */
	PageNo        uint32   /* 08-11: Current page number. */
	Magic         uint32   /* 12-15: Magic number. */
	Version       uint32   /* 16-19: Version. */
	PageSize      uint32   /* 20-23: Pagesize. */
	EncryptionAlg uint8    /*    24: Encryption algorithm. */
	PageType      uint8    /*    25: Page type. */
	MetaFlags     uint8    /* 26: Meta-only flags */
	Unused1       uint8    /* 27: Unused. */
	Free          uint32   /* 28-31: Free list page number. */
	LastPageNo    uint32   /* 32-35: Page number of last page in db. */
	NParts        uint32   /* 36-39: Number of partitions. */
	KeyCount      uint32   /* 40-43: Cached key count. */
	RecordCount   uint32   /* 44-47: Cached record count. */
	Flags         uint32   /* 48-51: Flags: unique to each AM. */
	UniqueFileID  [19]byte /* 52-71: Unique file ID. */
}
type HashMetadataPage struct {
	GenericMetadataPageHeader
	MaxBucket   uint32 /* 72-75: ID of Maximum bucket in use */
	HighMask    uint32 /* 76-79: Modulo mask into table */
	LowMask     uint32 /* 80-83: Modulo mask into table lower half */
	FillFactor  uint32 /* 84-87: Fill factor */
	NumKeys     uint32 /* 88-91: Number of keys in hash table */
	CharKeyHash uint32 /* 92-95: Value of hash(CHARKEY) */
	// don't care about the rest...
}
type HashPageHeader struct {
	LSN            [8]byte /* 00-07: LSN. */
	PageNo         uint32  /* 08-11: Current page number. */
	PreviousPageNo uint32  /* 12-15: Previous page number. */
	NextPageNo     uint32  /* 16-19: Next page number. */
	NumEntries     uint16  /* 20-21: Number of items on the page. */
	FreeAreaOffset uint16  /* 22-23: High free byte page offset. */
	TreeLevel      uint8   /*    24: Btree tree level. */
	PageType       uint8   /*    25: Page type. */
}
type HashOffPageEntry struct {
	PageType uint8   /*    0: Page type. */
	Unused   [3]byte /* 01-03: Padding, unused. */
	PageNo   uint32  /* 04-07: Offpage page number. */
	Length   uint32  /* 08-11: Total length of item. */
}
type RPMEntryInfo struct {
	Tag    int32  /*!< Tag identifier. */
	Type   uint32 /*!< Tag data type. */
	Offset int32  /*!< Offset into data segment (ondisk only). */
	Count  uint32 /*!< Number of tag elements. */
}
type FileInfo struct {
	Path   string
	Digest string
}
type Package struct {
	Epoch           int32
	Name            string
	Version         string
	Release         string
	Arch            string
	SourceRpm       string
	Size            int32
	License         string
	Vendor          string
	DigestAlgorithm DigestAlgorithm
	Files           []FileInfo
}

type Database struct {
	metadata HashMetadataPage
	f        *os.File
}
type WalkFunc func(p Package)

func (db *Database) WalkPackages(f WalkFunc) (err error) {
	pd := make([]byte, db.metadata.PageSize)
	for pno := 0; pno < int(db.metadata.LastPageNo); pno++ {
		_, err = io.ReadFull(db.f, pd)
		if err != nil {
			return
		}
		var current int64
		current, err = db.f.Seek(0, io.SeekCurrent)
		if err != nil {
			return
		}
		hdr := HashPageHeader{}
		pr := bytes.NewReader(pd)
		err = binary.Read(pr, binary.LittleEndian, &hdr)
		if err != nil {
			return
		}
		if hdr.PageType != HashPageType {
			continue
		}
		if hdr.NumEntries%2 != 0 {
			continue
		}
		indexes := []uint16{}
		for eno := 0; eno < int(hdr.NumEntries)/2; eno++ {
			_, err = pr.Seek(IndexSize, io.SeekCurrent)
			if err != nil {
				return
			}
			var index uint16
			err = binary.Read(pr, binary.LittleEndian, &index)
			if err != nil {
				return
			}
			if pd[index] == HashOffIndexPageType {
				indexes = append(indexes, index)
			}
		}
		for _, index := range indexes {
			_, err = pr.Seek(int64(index), io.SeekStart)
			if err != nil {
				return
			}
			e := HashOffPageEntry{}
			err = binary.Read(pr, binary.LittleEndian, &e)
			if err != nil {
				return
			}
			buf := bytes.NewBuffer(make([]byte, 0, e.Length))
			// sub-pd
			spd := make([]byte, db.metadata.PageSize)
			for spno := e.PageNo; spno != 0; {
				_, err = db.f.Seek(int64(spno*db.metadata.PageSize), io.SeekStart)
				if err != nil {
					return
				}
				_, err = io.ReadFull(db.f, spd)
				if err != nil {
					return
				}
				// sub-pr
				spr := bytes.NewReader(spd)
				// sub-hdr
				shdr := HashPageHeader{}
				err = binary.Read(spr, binary.LittleEndian, &shdr)
				if err != nil {
					return
				}
				if shdr.PageType != OverflowPageType {
					continue
				}
				if shdr.NextPageNo == 0 {
					buf.Write(spd[HashPageHeaderSize : HashPageHeaderSize+shdr.FreeAreaOffset])
				} else {
					buf.Write(spd[HashPageHeaderSize:])
				}
				spno = shdr.NextPageNo
			}
			var il, dl uint32
			err = binary.Read(buf, binary.BigEndian, &il)
			if err != nil {
				return
			}
			err = binary.Read(buf, binary.BigEndian, &dl)
			if err != nil {
				return
			}
			eis := make([]RPMEntryInfo, 0, il)
			for i := 0; i < int(il); i++ {
				ei := RPMEntryInfo{}
				err = binary.Read(buf, binary.BigEndian, &ei)
				if err != nil {
					return
				}
				eis = append(eis, ei)
			}
			eis = eis[1:]
			dt := buf.Bytes()
			p := Package{}
			var dirNames, baseNames, digests []string
			var dirIndexes []int32
		out:
			for i, ei := range eis {
				var edt []byte
				if i != len(eis)-1 {
					edt = dt[ei.Offset:eis[i+1].Offset]
				} else {
					edt = dt[ei.Offset:dl]
				}
				switch ei.Tag {
				case RPMTAG_DIRINDEXES:
					if ei.Type != RPM_INT32_TYPE {
						break out
					}
					dirIndexes = decodeInt32Array(edt)
				case RPMTAG_DIRNAMES:
					if ei.Type != RPM_STRING_ARRAY_TYPE {
						break out
					}
					dirNames = decodeStringArray(edt)
				case RPMTAG_BASENAMES:
					if ei.Type != RPM_STRING_ARRAY_TYPE {
						break out
					}
					baseNames = decodeStringArray(edt)
				case RPMTAG_NAME:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.Name = string(bytes.TrimRight(edt, "\x00"))
				case RPMTAG_EPOCH:
					if ei.Type != RPM_INT32_TYPE {
						break out
					}
					if err := binary.Read(bytes.NewReader(edt), binary.BigEndian, &p.Epoch); err != nil {
						break out
					}
				case RPMTAG_VERSION:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.Version = string(bytes.TrimRight(edt, "\x00"))
				case RPMTAG_RELEASE:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.Release = string(bytes.TrimRight(edt, "\x00"))
				case RPMTAG_ARCH:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.Arch = string(bytes.TrimRight(edt, "\x00"))
				case RPMTAG_SOURCERPM:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.SourceRpm = string(bytes.TrimRight(edt, "\x00"))
					if p.SourceRpm == "(none)" {
						p.SourceRpm = ""
					}
				case RPMTAG_LICENSE:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.License = string(bytes.TrimRight(edt, "\x00"))
					if p.License == "(none)" {
						p.License = ""
					}
				case RPMTAG_VENDOR:
					if ei.Type != RPM_STRING_TYPE {
						break out
					}
					p.Vendor = string(bytes.TrimRight(edt, "\x00"))
					if p.Vendor == "(none)" {
						p.Vendor = ""
					}
				case RPMTAG_SIZE:
					if ei.Type != RPM_INT32_TYPE {
						break out
					}
					if err := binary.Read(bytes.NewReader(edt), binary.BigEndian, &p.Size); err != nil {
						break out
					}
				case RPMTAG_FILEDIGESTALGO:
					if ei.Type != RPM_INT32_TYPE {
						break out
					}
					if err := binary.Read(bytes.NewReader(edt), binary.BigEndian, &p.DigestAlgorithm); err != nil {
						break out
					}
				case RPMTAG_FILEDIGESTS:
					if ei.Type != RPM_STRING_ARRAY_TYPE {
						break out
					}
					digests = decodeStringArray(edt)
				}
			}
			p.Files = joinFiles(dirNames, baseNames, digests, dirIndexes)
			f(p)
		}
		_, err = db.f.Seek(current, io.SeekStart)
		if err != nil {
			return
		}
	}
	return
}
func (db *Database) Close() {
	db.f.Close()
}
func decodeStringArray(dt []byte) (ret []string) {
	elements := strings.Split(string(dt), "\x00")
	if len(elements) > 0 && elements[len(elements)-1] == "" {
		return elements[:len(elements)-1]
	}
	return elements
}
func decodeInt32Array(dt []byte) (ret []int32) {
	r := bytes.NewReader(dt)
	for {
		i := int32(0)
		err := binary.Read(r, binary.BigEndian, &i)
		if err != nil {
			break
		}
		ret = append(ret, i)
	}
	return
}
func joinFiles(dirNames, baseNames, digests []string, dirIndexes []int32) []FileInfo {
	files := []FileInfo{}
	if len(dirNames) == 0 || len(baseNames) == 0 || len(dirIndexes) == 0 ||
		len(dirIndexes) != len(baseNames) || len(dirNames) > len(baseNames) {
		return files
	}
	for i, bn := range baseNames {
		f := FileInfo{
			Path: filepath.Join(dirNames[dirIndexes[i]], bn),
		}
		if len(digests) > i {
			f.Digest = digests[i]
		}
		files = append(files, f)
	}
	return files
}
func OpenDatabase() (db *Database, err error) {
	var f *os.File
	f, err = os.Open("/var/lib/rpm/Packages")
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	metadata := HashMetadataPage{}
	err = binary.Read(f, binary.LittleEndian, &metadata)
	if err != nil {
		return
	}
	if metadata.Magic != HashMagicNumber {
		err = errors.New("invalid magic number")
		return
	}
	if metadata.PageType != HashMetadataPageType {
		err = errors.New("invalid hash metadata page type")
		return
	}
	_, err = f.Seek(int64(metadata.PageSize), io.SeekStart)
	if err != nil {
		return
	}
	db = &Database{
		metadata,
		f,
	}
	return
}
