package GoSNMPServer

import (
	"github.com/pkg/errors"
	"github.com/slayercat/gosnmp"
	"strconv"
	"strings"
)

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
func IsValidObjectIdentifier(oid string) error {
	xi := strings.Split(oid, ".")
	for id, each := range xi {
		if each == "" {
			if id == 0 {
				continue
			} else {
				return errors.Errorf("oidToByteString not valid id. value=%v", oid)
			}
		}
		i, err := strconv.ParseInt(each, 10, 32)
		if err != nil || i < 0 {
			return errors.Errorf("oidToByteString not valid id. value=%v", oid)
		}
	}
	return nil
}
