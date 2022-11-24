package virus_detection

const (
	VirusScanDataTypeQuick int32 = 6057
	VirusScanDataTypeFull  int32 = 6057
	VirusScanDataTypeFile  int32 = 6053
)

const (
	VirusScanTaskTypeQuick = "scan_quick"
	VirusScanTaskTypeFull  = "scan_full"
	VirusScanTaskTypeFile  = "scan_file"
)

var VirusTaskActionList = [3]string{
	VirusScanTaskTypeQuick, VirusScanTaskTypeFull, VirusScanTaskTypeFile,
}
