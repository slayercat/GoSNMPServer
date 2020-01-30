package GoSNMPServer

import "github.com/slayercat/gosnmp"

// PermissionAllowance  ENUM controls for Allowance
type PermissionAllowance int

// PermissionAllowanceAllowed allowed for access
const PermissionAllowanceAllowed PermissionAllowance = 0

// PermissionAllowanceDenied denies for access
const PermissionAllowanceDenied PermissionAllowance = 1

type FuncPDUControlCheckPermission func(pktVersion gosnmp.SnmpVersion, pduType gosnmp.PDUType, contextName string) PermissionAllowance

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

	//////////// For human document

	//Document for this PDU Item. ignored by the program.
	Document string
}
