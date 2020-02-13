package ucdMib

import "github.com/slayercat/GoSNMPServer"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
}

func All() []*GoSNMPServer.PDUValueControlItem {
	var result []*GoSNMPServer.PDUValueControlItem
	result = append(result, MemoryOIDs()...)
	result = append(result, SystemStatsOIDs()...)
	result = append(result, NetworkOIDs()...)

	return result

}
