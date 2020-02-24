package GoSNMPServer

import (
	"net"

	"github.com/pkg/errors"
	"github.com/slayercat/gosnmp"
)

// PermissionAllowance  ENUM controls for Allowance
type PermissionAllowance int

// PermissionAllowanceAllowed allowed for access
const PermissionAllowanceAllowed PermissionAllowance = 0

// PermissionAllowanceDenied denies for access
const PermissionAllowanceDenied PermissionAllowance = 1

//FuncPDUControlCheckPermission checks for permission.
//   return PermissionAllowanceAllowed / PermissionAllowanceDenied
type FuncPDUControlCheckPermission func(pktVersion gosnmp.SnmpVersion, pduType gosnmp.PDUType, contextName string) PermissionAllowance

//FuncPDUControlTrap will be called on trap.
//    args:
//		isInform: indicate if the request is a InformRequest.
//          true  -- It's a InformRequest. data will be returns to the client
//			false -- It's a trap.  data to returned will drop silencely.
// 		trapdata: what client asks for.
//    returns:
//		dataret -- try to return to client. nil for nothing to return
//		err  --  any error?(will return to client by string)
type FuncPDUControlTrap func(isInform bool, trapdata gosnmp.SnmpPDU) (dataret *gosnmp.SnmpPDU, err error)

// FuncPDUControlGet will be called on get value
type FuncPDUControlGet func() (value interface{}, err error)

// FuncPDUControlSet will be called on set value
type FuncPDUControlSet func(value interface{}) error

// PDUValueControlItem describe the action of get / set / walk in pdu tree
type PDUValueControlItem struct {
	// OID controls which OID does this PDUValue works
	OID string
	// Type defines which type this OID is.
	Type gosnmp.Asn1BER

	// NonWalkable marks this oid as not walkable. It **WILL NOT** returned in walk items. but do retuend
	//             in direct get.
	//             All write only item will be NonWalkable
	NonWalkable bool

	/////////// Callbacks

	// OnCheckPermission will be called on access this OID. set to nil to allow all access.
	//     return PermissionAllowanceAllowed for allow this access.
	//            (otherwrise) PermissionAllowanceDenied for disable access.
	OnCheckPermission FuncPDUControlCheckPermission

	// OnGet will be called on any GET / walk option. set to nil for mark this as a write-only item
	OnGet FuncPDUControlGet
	// OnSet will be called on any Set option. set to nil for mark as a read-only item.
	OnSet FuncPDUControlSet
	// OnTrap will be called on TRAP.
	OnTrap FuncPDUControlTrap
	//////////// For human document

	//Document for this PDU Item. ignored by the program.
	Document string
}

func Asn1IntegerUnwrap(i interface{}) int { return i.(int) }
func Asn1IntegerWrap(i int) interface{}   { return i }

func Asn1OctetStringUnwrap(i interface{}) string {
	switch i.(type) {
	case string:
		return i.(string)
	default:
		return string(i.([]uint8))
	}
}
func Asn1OctetStringWrap(i string) interface{} { return i }

func Asn1ObjectIdentifierUnwrap(i interface{}) string { return i.(string) }
func Asn1ObjectIdentifierWrap(i string) interface{}   { return i }

func Asn1IPAddressUnwrap(i interface{}) net.IP {
	ip := net.ParseIP(i.(string))
	if ip == nil {
		panic(errors.Errorf("not valid ip: %v", i))
	}
	return ip
}
func Asn1IPAddressWrap(i net.IP) interface{} {
	return i
}

func Asn1Counter32Unwrap(i interface{}) uint { return i.(uint) }
func Asn1Counter32Wrap(i uint) interface{}   { return i }

func Asn1Gauge32Unwrap(i interface{}) uint { return i.(uint) }
func Asn1Gauge32Wrap(i uint) interface{}   { return i }

func Asn1TimeTicksUnwrap(i interface{}) uint32 { return i.(uint32) }
func Asn1TimeTicksWrap(i uint32) interface{}   { return i }

func Asn1Counter64Unwrap(i interface{}) uint64 { return i.(uint64) }
func Asn1Counter64Wrap(i uint64) interface{}   { return i }

func Asn1Uinteger32Unwrap(i interface{}) uint32 { return i.(uint32) }
func Asn1Uinteger32Wrap(i uint32) interface{}   { return i }

func Asn1OpaqueFloatUnwrap(i interface{}) float32 { return i.(float32) }
func Asn1OpaqueFloatWrap(i float32) interface{}   { return i }

func Asn1OpaqueDoubleUnwrap(i interface{}) float64 { return i.(float64) }
func Asn1OpaqueDoubleWrap(i float64) interface{}   { return i }

type byOID []*PDUValueControlItem

func (x byOID) Len() int {
	return len(x)
}

func (x byOID) Less(i, j int) bool {
	stripedI := oidToByteString(x[i].OID)
	stripedJ := oidToByteString(x[j].OID)
	return stripedI < stripedJ
}

func (x byOID) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}
