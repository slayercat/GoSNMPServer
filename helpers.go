package GoSNMPServer

import "github.com/slayercat/gosnmp"

func getPktContextOrCommunity(i *gosnmp.SnmpPacket) string {
	if i.Version == gosnmp.Version3 {
		return i.ContextName
	} else {
		return i.Community
	}
}

func copySnmpPacket(i *gosnmp.SnmpPacket) gosnmp.SnmpPacket {
	var ret gosnmp.SnmpPacket = *i
	if i.SecurityParameters != nil {
		ret.SecurityParameters = i.SecurityParameters.Copy()
	}
	return ret
}
