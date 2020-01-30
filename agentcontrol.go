package GoSNMPServer

import "time"
import "strings"
import "github.com/shirou/gopsutil/host"

import "github.com/slayercat/gosnmp"
import "github.com/pkg/errors"

type FuncGetAuthoritativeEngineTime func() uint32

//MasterAgent identifys software which runs on managed devices
//            One server (port) could ONLY have one MasterAgent
type MasterAgent struct {
	// AuthoritativeEngineID is SNMPV3 AuthoritativeEngineID
	AuthoritativeEngineID SNMPEngineID
	// AuthoritativeEngineBoots is SNMPV3 AuthoritativeEngineBoots
	AuthoritativeEngineBoots uint32
	// OnGetAuthoritativeEngineTime will be called to get SNMPV3 AuthoritativeEngineTime
	//      if sets to nil, the sys boottime will be used
	OnGetAuthoritativeEngineTime FuncGetAuthoritativeEngineTime

	SecurityConfig SecurityConfig

	SubAgents []SubAgent

	Logger ILogger

	priv struct {
		communityToSubAgent map[string]*SubAgent
		defaultSubAgent     *SubAgent
	}
}

type SubAgent struct {
	// ContextName selects from SNMPV3 ContextName or SNMPV1/V2c community for switch from SubAgent...
	//             set to nil means all requests will gets here(of default)

	CommunityIDs []string

	// OIDs for Read/Write actions
	OIDs []PDUValueControlItem

	Logger ILogger
}

type SecurityConfig struct {
	NoSecurity bool
}

type SNMPEngineID struct {
	// TODO!
	// See https://tools.ietf.org/html/rfc3411#section-5
	// 			SnmpEngineID ::= TEXTUAL-CONVENTION
	EngineIDData string
}

func (t *SNMPEngineID) Marshal() []byte {
	// XXX: STUB

	// msgAuthoritativeEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
	// 1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
	// Engine Enterprise ID: pysnmp (20408)
	// Engine ID Format: Octets, administratively assigned (5)
	// Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8

	var tm []byte = []byte{
		0x80, 0x00, 0x4f, 0xb8, 0x05, 0x44, 0x45, 0x53,
		0x4b, 0x54, 0x4f, 0x50, 0x2d, 0x4a, 0x37, 0x32,
		0x53, 0x32, 0x45, 0x34, 0x3a, 0xb6, 0x3b, 0xc8,
	}
	return tm
}

func (t *MasterAgent) syncAndCheck() error {
	if len(t.SubAgents) == 0 {
		return errors.WithStack(errors.Errorf("MasterAgent shell have at least one SubAgents"))
	}
	if t.SecurityConfig.NoSecurity && len(t.SubAgents) != 1 {
		return errors.WithStack(errors.Errorf("NoSecurity MasterAgent shell have one one SubAgent"))
	}

	if t.Logger == nil {
		//Set New NIL Logger
		t.Logger = NewDiscardLogger()
	}
	if t.OnGetAuthoritativeEngineTime == nil {
		t.OnGetAuthoritativeEngineTime = DefaultGetAuthoritativeEngineTime
	}

	for _, each := range t.SubAgents {
		each.Logger = t.Logger
	}

	if t.AuthoritativeEngineID.EngineIDData == "" {
		t.AuthoritativeEngineID = DefaultAuthoritativeEngineID()
	}
	return nil
}

func (t *MasterAgent) ReadyForWork() error {
	if err := t.syncAndCheck(); err != nil {
		return err
	}
	return t.SyncConfig()
}

func (t *MasterAgent) ResponseForBuffer(i []byte) (*gosnmp.SnmpPacket, error) {
	// Decode
	vhandle := gosnmp.GoSNMP{}
	vhandle.Logger = &SnmpLoggerAdapter{t.Logger}
	request, err := vhandle.SnmpDecodePacket(i)

	switch request.Version {
	case gosnmp.Version1, gosnmp.Version2c:
		return t.ResponseForPkt(request)
	case gosnmp.Version3:
		_ = err
		//v3 might want for Privacy
		fallthrough
	default:
		return nil, errors.WithStack(ErrUnsupportedProtoVersion)
	}
}

func (t *MasterAgent) ResponseForPkt(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	// Find for which SubAgent
	community := t.getPktContextOrCommunity(i)
	subAgent := t.findForSubAgent(community)
	if subAgent == nil {
		return nil, errors.WithStack(ErrNoSNMPInstance)
	}

	return subAgent.Serve(i)
	//return nil, ErrUnsupportedProtoVersion
}

func (t *MasterAgent) SyncConfig() error {
	t.priv.defaultSubAgent = nil
	t.priv.communityToSubAgent = make(map[string]*SubAgent)
	for id := range t.SubAgents {
		current := &t.SubAgents[id]
		if len(current.CommunityIDs) == 0 {
			if t.priv.defaultSubAgent != nil {
				return errors.Errorf("SyncConfig: Config Error: duplicate default agent")
			}
			t.priv.defaultSubAgent = current
			continue
		}
		for _, val := range current.CommunityIDs {
			if _, exists := t.priv.communityToSubAgent[val]; exists {
				return errors.Errorf("SyncConfig: Config Error: duplicate value:%s", val)
			}
			t.priv.communityToSubAgent[val] = current
		}

		if err := current.SyncConfig(); err != nil {
			return err
		}
	}
	return nil
}

func (t *MasterAgent) getPktContextOrCommunity(i *gosnmp.SnmpPacket) string {
	if i.Version == gosnmp.Version3 {
		return i.ContextName
	} else {
		return i.Community
	}
}

func (t *MasterAgent) findForSubAgent(community string) *SubAgent {
	if val, ok := t.priv.communityToSubAgent[community]; ok {
		return val
	} else {
		return t.priv.defaultSubAgent
	}
}

func (t *SubAgent) SyncConfig() error {
	//TODO: here
	return nil
}

func (t *SubAgent) Serve(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	//find for oid
	panic("NotIMP	")
}

func (t *SubAgent) GetOID(oid string) (interface{}, error) {
	//find for oid
	item, err := t.getForPDUValueControl(oid)
	if err != nil {
		return nil, err
	}
	if item.OnGet == nil {
		return nil, errors.WithStack(ErrUnsupportedOperation)
	}

	panic("XXX")

}

func (t *SubAgent) SetOID(oid string, value interface{}) error {
	//find for oid
	panic("XXX")
}

func (t *SubAgent) getForPDUValueControl(oid string) (*PDUValueControlItem, error) {
	striped := strings.Trim(oid, ".")
	for id, val := range t.OIDs {
		if val.OID == oid || val.OID == striped {
			return &t.OIDs[id], nil
		}
	}
	return nil, errors.WithStack(ErrUnknownOID)
}

func DefaultAuthoritativeEngineID() SNMPEngineID {
	// XXX:TODO: return random
	return SNMPEngineID{
		EngineIDData: "xxxx",
	}
}

func DefaultGetAuthoritativeEngineTime() uint32 {
	val, err := host.Uptime()
	if err != nil {
		return uint32(time.Now().Unix())
	}
	return uint32(val)
}
