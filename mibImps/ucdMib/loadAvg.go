package ucdMib

import "fmt"
import "github.com/slayercat/gosnmp"
import "github.com/slayercat/GoSNMPServer"
import "github.com/shirou/gopsutil/load"

// SystemLoadOIDs Returns a list of system Load.
//   see http://www.net-snmp.org/docs/mibs/ucdavis.html#DisplayString
func SystemLoadOIDs() []*GoSNMPServer.PDUValueControlItem {
	return []*GoSNMPServer.PDUValueControlItem{
		{
			OID:      "1.3.6.1.4.1.2021.10.1.1.1",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(1), nil },
			Document: "laIndex",
		},
		{
			OID:      "1.3.6.1.4.1.2021.10.1.2.1",
			Type:     gosnmp.OctetString,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("Load-1"), nil },
			Document: "laNames",
		},
		{
			OID:  "1.3.6.1.4.1.2021.10.1.3.1",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1OctetStringWrap(fmt.Sprintf("%v", val.Load1)), nil
				}
			},
			Document: "laLoad(float->OctetString)",
		},
		{
			OID:  "1.3.6.1.4.1.2021.10.1.5.1",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Load1)), nil
				}
			},
			Document: "laLoadInt",
		},
		/////  5Min
		{
			OID:      "1.3.6.1.4.1.2021.10.1.1.2",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(2), nil },
			Document: "laIndex",
		},
		{
			OID:      "1.3.6.1.4.1.2021.10.1.2.2",
			Type:     gosnmp.OctetString,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("Load-5"), nil },
			Document: "laNames",
		},
		{
			OID:  "1.3.6.1.4.1.2021.10.1.3.2",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1OctetStringWrap(fmt.Sprintf("%v", val.Load5)), nil
				}
			},
			Document: "laLoad(float->OctetString)",
		},
		{
			OID:  "1.3.6.1.4.1.2021.10.1.5.2",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Load5)), nil
				}
			},
			Document: "laLoadInt",
		},
		/////  15 min
		{
			OID:      "1.3.6.1.4.1.2021.10.1.1.3",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(3), nil },
			Document: "laIndex",
		},
		{
			OID:      "1.3.6.1.4.1.2021.10.1.2.3",
			Type:     gosnmp.OctetString,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("Load-15"), nil },
			Document: "laNames",
		},
		{
			OID:  "1.3.6.1.4.1.2021.10.1.3.3",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1OctetStringWrap(fmt.Sprintf("%v", val.Load15)), nil
				}
			},
			Document: "laLoad(float->OctetString)",
		},
		{
			OID:  "1.3.6.1.4.1.2021.10.1.5.3",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Load15)), nil
				}
			},
			Document: "laLoadInt",
		},
	}
}
