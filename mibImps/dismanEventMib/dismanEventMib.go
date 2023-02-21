package dismanEventMib

import "github.com/slayercat/gosnmp"
import "github.com/Chien-W/GoSNMPServer"
import "github.com/shirou/gopsutil/host"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

// SetupLogger Setups Logger for this mib
func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
}

// DismanEventOids function provides sysUptime
//
//	see http://www.oid-info.com/get/1.3.6.1.2.1.1.3.0
//	    http://www.net-snmp.org/docs/mibs/dismanEventMIB.html
func DismanEventOids() []*GoSNMPServer.PDUValueControlItem {
	return []*GoSNMPServer.PDUValueControlItem{
		{
			OID:  "1.3.6.1.2.1.1.3.0",
			Type: gosnmp.TimeTicks,
			OnGet: func() (value interface{}, err error) {
				if val, err := host.Uptime(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1TimeTicksWrap(uint32(val)), nil
				}
			},
			Document: "Uptime",
		},
	}
}

// All function provides a list of common used OID in DISMAN-EVENT-MIB
func All() []*GoSNMPServer.PDUValueControlItem {
	return DismanEventOids()
}
