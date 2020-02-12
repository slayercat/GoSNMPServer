package ucdMib

import "github.com/slayercat/gosnmp"
import "github.com/slayercat/GoSNMPServer"
import "github.com/shirou/gopsutil/mem"

// MemoryOIDs Returns a list of memory operation.
//   see http://www.net-snmp.org/docs/mibs/ucdavis.html#DisplayString
func AllMemoryOIDs() []*GoSNMPServer.PDUValueControlItem {
	return []*GoSNMPServer.PDUValueControlItem{
		{
			OID:      "1.3.6.1.4.1.2021.4.1",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(0), nil },
			Document: "memIndex",
		},
		{
			OID:      "1.3.6.1.4.1.2021.4.2",
			Type:     gosnmp.OctetString,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("swap"), nil },
			Document: "memErrorName",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.3",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.SwapMemory(); err == nil {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Total / 1024)), nil
				} else {
					return nil, err
				}
			},
			Document: "memTotalSwap",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.4",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.SwapMemory(); err == nil {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Free / 1024)), nil
				} else {
					return nil, err
				}
			},
			Document: "memAvailSwap",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.5",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.VirtualMemory(); err == nil {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Total / 1024)), nil
				} else {
					return nil, err
				}
			},
			Document: "memTotalReal",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.5",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.VirtualMemory(); err == nil {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Available / 1024)), nil
				} else {
					return nil, err
				}
			},
			Document: "memAvailReal",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.11",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.VirtualMemory(); err == nil {
					if valSwap, errSwap := mem.SwapMemory(); errSwap == nil {
						return GoSNMPServer.Asn1IntegerWrap(int((val.Available + valSwap.Free) / 1024)), nil
					} else {
						return nil, errSwap
					}
				} else {
					return nil, err
				}
			},
			Document: "memTotalFree",
		},
		{
			OID:      "1.3.6.1.4.1.2021.4.12",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(0), nil },
			Document: "memMinimumSwap",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.14",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.VirtualMemory(); err == nil {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Buffers / 1024)), nil
				} else {
					return nil, err
				}
			},
			Document: "memBuffer",
		},
		{
			OID:  "1.3.6.1.4.1.2021.4.15",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := mem.VirtualMemory(); err == nil {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Cached / 1024)), nil
				} else {
					return nil, err
				}
			},
			Document: "memCached",
		},
		{
			OID:      "1.3.6.1.4.1.2021.4.100",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(0), nil },
			Document: "memSwapError",
		},
		{
			OID:      "1.3.6.1.4.1.2021.4.100",
			Type:     gosnmp.OctetString,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap(""), nil },
			Document: "memSwapErrorMsg",
		},
	}
}
