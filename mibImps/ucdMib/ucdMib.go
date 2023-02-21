package ucdMib

import "github.com/Chien-W/GoSNMPServer"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

// SetupLogger Setups Logger for this mib
func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
}

// All function provides a list of common used OID in UCD-MIB
func All() []*GoSNMPServer.PDUValueControlItem {
	var result []*GoSNMPServer.PDUValueControlItem
	result = append(result, MemoryOIDs()...)
	result = append(result, SystemStatsOIDs()...)
	result = append(result, SystemLoadOIDs()...)
	result = append(result, DiskUsageOIDs()...)
	return result

}
