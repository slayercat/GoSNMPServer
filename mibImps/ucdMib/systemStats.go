package ucdMib

import (
	"github.com/slayercat/gosnmp"
	"time"
)
import "github.com/Chien-W/GoSNMPServer"
import "github.com/shirou/gopsutil/cpu"
import "github.com/shirou/gopsutil/disk"
import "github.com/prometheus/procfs"

// SystemStatsOIDs Returns a list of memory operation.
//
//	see http://www.net-snmp.org/docs/mibs/ucdavis.html#DisplayString
func SystemStatsOIDs() []*GoSNMPServer.PDUValueControlItem {
	toRet := []*GoSNMPServer.PDUValueControlItem{
		{
			OID:      "1.3.6.1.4.1.2021.11.1",
			Type:     gosnmp.Integer,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(0), nil },
			Document: "ssIndex",
		},
		{
			OID:      "1.3.6.1.4.1.2021.11.2",
			Type:     gosnmp.OctetString,
			OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("systemStats"), nil },
			Document: "ssErrorName",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.50",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].User)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawUser",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.51",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Nice)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawNice",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.52",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].System)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawSystem",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.53",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					time.Sleep(2 * time.Second)
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Idle)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawIdle",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.54",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Iowait)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawWait",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.56",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Irq)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawInterrupt",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.57",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := disk.IOCounters(); err == nil {
					var sum uint64
					for _, value := range val {
						sum += value.WriteCount
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(sum)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssIORawSent",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.58",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := disk.IOCounters(); err == nil {
					var sum uint64
					for _, value := range val {
						sum += value.ReadCount
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(sum)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssIORawReceived",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.61",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Softirq)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawSoftIRQ",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.64",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Steal)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawSteal",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.65",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := cpu.Times(false); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val[0].Guest)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssCpuRawGuest",
		},
	}

	appendLinuxPlatformSystemStats(&toRet)
	return toRet
}
func appendLinuxPlatformSystemStats(io *[]*GoSNMPServer.PDUValueControlItem) {
	procfsInt, err := procfs.NewDefaultFS()
	if err != nil {
		return
	}
	toAppend := []*GoSNMPServer.PDUValueControlItem{
		{
			OID:  "1.3.6.1.4.1.2021.11.59",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := procfsInt.NewStat(); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val.IRQTotal)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssRawInterrupts",
		},
		{
			OID:  "1.3.6.1.4.1.2021.11.60",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				if val, err := procfsInt.NewStat(); err == nil {
					return GoSNMPServer.Asn1Counter32Wrap(uint(val.ContextSwitches)), nil
				} else {
					return nil, err
				}
			},
			Document: "ssRawContexts",
		},
	}
	*io = append(*io, toAppend...)
}
