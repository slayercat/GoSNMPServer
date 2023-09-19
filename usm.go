package GoSNMPServer

import (
	"github.com/gosnmp/gosnmp"
)

func GenKeys(sp *gosnmp.UsmSecurityParameters) {
	err := sp.InitSecurityKeys()
	if err != nil {
		panic(err)
	}
}

func GenSalt(sp *gosnmp.UsmSecurityParameters) {
	dummy := &gosnmp.SnmpPacket{MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: sp}
	//InitPacket will increment the salt if a packet with AuthPriv set
	// is used as input
	err := sp.InitPacket(dummy)
	if err != nil {
		panic(err)
	}
}
