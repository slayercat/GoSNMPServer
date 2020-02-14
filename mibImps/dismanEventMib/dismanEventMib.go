package dismanEventMib

import "github.com/slayercat/gosnmp"
import "github.com/slayercat/GoSNMPServer"
import "github.com/shirou/gopsutil/host"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
}

func DismanEventOids() []*GoSNMPServer.PDUValueControlItem {
	return []*GoSNMPServer.PDUValueControlItem{
		{
			OID:  "1.3.6.1.2.1.1.3.0",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := host.Uptime(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val)), nil
				}
			},
			Document: "Uptime",
		},
	}
}

func All() []*GoSNMPServer.PDUValueControlItem {
	return DismanEventOids()
}
