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

// Fix BUG: When converting certain byte values to the rune type,
// some byte values may not be represented correctly because the rune type represents a Unicode character.
// This can cause byte values to become unpredictable or incorrect after conversion.
func oidToByteString(oid string) string {
	return oid
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
