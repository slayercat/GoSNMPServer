package GoSNMPServer

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
	xi := strings.Split(oid, ".")
	out := []rune{}
	for _, each := range xi {
		if each == "" {
			continue
		}
		i, err := strconv.ParseInt(each, 10, 32)
		if err != nil {
			panic(err)
		}
		out = append(out, rune(i))
	}
	return string(out)
}
