package GoSNMPServer

import "encoding/asn1"
import "github.com/pkg/errors"
import "github.com/slayercat/gosnmp"
import "strings"
import "strconv"

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

func oidToByteString(oid string) string {
	oid = strings.TrimLeft(oid, ".")

	components := strings.Split(oid, ".")
	obj := make([]int, len(components))
	for i, c := range components {
		num, err := strconv.Atoi(c)
		if err != nil {
			panic(err)
		}
		obj[i] = num
	}
	oidBytes, err := asn1.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return string(oidBytes), nil
}

// IsValidObjectIdentifier will check a oid string is valid oid
func IsValidObjectIdentifier(oid string) (result bool) {
	defer func() {
		if err := recover(); err != nil {
			result = false
			return
		}
	}()
	if len(oid) == 0 {
		return false
	}
	oidToByteString(oid)
	return true
}
