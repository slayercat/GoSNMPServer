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

// IsValidObjectIdentifier will check an oid string is valid oid
// Deprecated: instead use VerifyOid.
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

// VerifyOid will check an oid string is valid oid,
// each number should be positive uint32.
func VerifyOid(oid string) error {
	xi := strings.Split(oid, ".")
	for id, each := range xi {
		if each == "" {
			if id == 0 {
				continue
			}
			return errors.New("oidToByteString not valid int,but it is empty " + oid)
		}
		i, err := strconv.ParseUint(each, 10, 32)
		if err != nil {
			return errors.New("oidToByteString not valid int. value=" + each)
		} else if i < 0 {
			return errors.New("oidToByteString not valid int. value=" + each + " should be positive")
		}
	}
	return nil
}
