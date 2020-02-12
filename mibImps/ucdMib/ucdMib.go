package ucdMib

import "github.com/slayercat/GoSNMPServer"

func All() []*GoSNMPServer.PDUValueControlItem {
	var result []*GoSNMPServer.PDUValueControlItem
	result = append(result, MemoryOIDs()...)
	result = append(result, SystemStatsOIDs()...)

	return result

}
