package ifMib

import "github.com/Chien-W/GoSNMPServer"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

// SetupLogger Setups Logger for this mib
func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
}

// All function provides a list of common used OID in IF-MIB
func All() []*GoSNMPServer.PDUValueControlItem {
	return NetworkOIDs()
}
