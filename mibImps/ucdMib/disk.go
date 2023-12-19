package ucdMib

import (
	"fmt"

	"github.com/gosnmp/gosnmp"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/slayercat/GoSNMPServer"
)

// NameOverride configs what path disk usage will returns.
type NameOverride struct {
	// RealPath in this pc.
	RealPath string

	// ShowName indicate what will it show in oid:
	//    in currentDskPath   1.3.6.1.4.1.2021.9.1.2.xxx
	//       currentDskDevice 1.3.6.1.4.1.2021.9.1.3.xxx
	ShowName string
}

// DiskUsageOIDs Returns a list of disk usages.
//
//	Args:
//	    showTheseNameOnly:  what path whill this oid returns. empty means all.
//	see http://www.net-snmp.org/docs/mibs/ucdavis.html#DisplayString
func DiskUsageOIDs(showTheseNameOnly ...NameOverride) []*GoSNMPServer.PDUValueControlItem {
	if len(showTheseNameOnly) == 0 {
		partitionStats, err := disk.Partitions(false)
		if err != nil {
			g_Logger.Errorf("Load partitionStats failed, err=%v", err)
			return []*GoSNMPServer.PDUValueControlItem{}
		}
		for _, val := range partitionStats {
			showTheseNameOnly = append(showTheseNameOnly, NameOverride{
				RealPath: val.Mountpoint,
				ShowName: val.Mountpoint,
			})
		}
	}
	toRet := []*GoSNMPServer.PDUValueControlItem{}
	for id, each := range showTheseNameOnly {
		cid := id + 1
		currentDiskItem := each
		thisDiskID := []*GoSNMPServer.PDUValueControlItem{
			{
				OID:      fmt.Sprintf("1.3.6.1.4.1.2021.9.1.1.%d", cid),
				Type:     gosnmp.Integer,
				OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(cid), nil },
				Document: "dskIndex",
			},
			{
				OID:  fmt.Sprintf("1.3.6.1.4.1.2021.9.1.2.%d", cid),
				Type: gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1OctetStringWrap(currentDiskItem.ShowName), nil
				},
				Document: "currentDskPath",
			},
			{
				OID:  fmt.Sprintf("1.3.6.1.4.1.2021.9.1.3.%d", cid),
				Type: gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) {
					return GoSNMPServer.Asn1OctetStringWrap(currentDiskItem.ShowName), nil
				},
				Document: "currentDskDevice",
			},
			{
				OID:  fmt.Sprintf("1.3.6.1.4.1.2021.9.1.6.%d", cid),
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					data, err := disk.Usage(currentDiskItem.RealPath)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1IntegerWrap(int(data.Total / 1024 / 1024)), nil
				},
				Document: "currentDskTotal",
			},
			{
				OID:  fmt.Sprintf("1.3.6.1.4.1.2021.9.1.7.%d", cid),
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					data, err := disk.Usage(currentDiskItem.RealPath)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1IntegerWrap(int(data.Free / 1024 / 1024)), nil
				},
				Document: "currentDskAvail",
			},
			{
				OID:  fmt.Sprintf("1.3.6.1.4.1.2021.9.1.8.%d", cid),
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					data, err := disk.Usage(currentDiskItem.RealPath)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1IntegerWrap(int(data.Used / 1024 / 1024)), nil
				},
				Document: "currentDskUsed",
			},
			{
				OID:  fmt.Sprintf("1.3.6.1.4.1.2021.9.1.9.%d", cid),
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					data, err := disk.Usage(currentDiskItem.RealPath)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1IntegerWrap(int(data.UsedPercent)), nil
				},
				Document: "currentDskPercent",
			},
		}
		toRet = append(toRet, thisDiskID...)
	}
	return toRet
}
