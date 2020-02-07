package GoSNMPServer

import "time"
import "strings"
import "reflect"
import "fmt"
import "github.com/shirou/gopsutil/host"

import "github.com/slayercat/gosnmp"
import "github.com/pkg/errors"

type FuncGetAuthoritativeEngineTime func() uint32

//MasterAgent identifys software which runs on managed devices
//            One server (port) could ONLY have one MasterAgent
type MasterAgent struct {
	SecurityConfig SecurityConfig

	SubAgents []*SubAgent

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

	master *MasterAgent
}

type SecurityConfig struct {
	NoSecurity bool

	// AuthoritativeEngineID is SNMPV3 AuthoritativeEngineID
	AuthoritativeEngineID SNMPEngineID
	// AuthoritativeEngineBoots is SNMPV3 AuthoritativeEngineBoots
	AuthoritativeEngineBoots uint32
	// OnGetAuthoritativeEngineTime will be called to get SNMPV3 AuthoritativeEngineTime
	//      if sets to nil, the sys boottime will be used
	OnGetAuthoritativeEngineTime FuncGetAuthoritativeEngineTime

	Users []gosnmp.UsmSecurityParameters
}

func (v *SecurityConfig) FindForUser(name string) *gosnmp.UsmSecurityParameters {
	if v.Users == nil {
		return nil
	}
	for item, user := range v.Users {
		if user.UserName == name {
			return &v.Users[item]
		}
	}
	return nil
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
	if t.SecurityConfig.OnGetAuthoritativeEngineTime == nil {
		t.SecurityConfig.OnGetAuthoritativeEngineTime = DefaultGetAuthoritativeEngineTime
	}

	if t.SecurityConfig.AuthoritativeEngineID.EngineIDData == "" {
		t.SecurityConfig.AuthoritativeEngineID = DefaultAuthoritativeEngineID()
	}
	return nil
}

func (t *MasterAgent) ReadyForWork() error {
	if err := t.syncAndCheck(); err != nil {
		return err
	}
	return t.SyncConfig()
}

func (t *MasterAgent) getUserNameFromRequest(request *gosnmp.SnmpPacket) string {
	var username string
	if val, ok := request.SecurityParameters.(*gosnmp.UsmSecurityParameters); !ok {
		panic(errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP .Unknown Type:%v", reflect.TypeOf(request.SecurityParameters)))
	} else {
		username = val.UserName
	}
	return username
}

func (t *MasterAgent) ResponseForBuffer(i []byte) ([]byte, error) {
	// Decode
	vhandle := gosnmp.GoSNMP{}
	vhandle.Logger = &SnmpLoggerAdapter{t.Logger}
	mb, _ := t.getUsmSecurityParametersFromUser("")
	vhandle.SecurityParameters = mb
	request, err := vhandle.SnmpDecodePacket(i)

	switch request.Version {
	case gosnmp.Version1, gosnmp.Version2c:
		return t.marshalPkt(t.ResponseForPkt(request))
		//
	case gosnmp.Version3:
		// check for initial - discover response / non Privacy Items
		if err == nil {
			val, err := t.ResponseForPkt(request)

			if val == nil {
				return t.marshalPkt(request, err)
			} else {
				return t.marshalPkt(val, err)
			}
		}
		//v3 might want for Privacy
		t.Logger.Debugf("v3 decode [will fail with non password] meet %v", err)
		if request.SecurityParameters == nil {
			return nil, errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP Returns %v", err)
		}
		username := t.getUserNameFromRequest(request)
		usm, err := t.getUsmSecurityParametersFromUser(username)
		if err != nil {
			return nil, err
		}
		vhandle.SecurityParameters = usm
		request, err := vhandle.SnmpDecodePacket(i)
		if err != nil {
			return nil, errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP Returns %v", err)
		}
		val, err := t.ResponseForPkt(request)
		if val == nil {
			request.SecurityParameters = usm
			return t.marshalPkt(request, err)
		} else {
			val.SecurityParameters = usm
			return t.marshalPkt(val, err)
		}
	}
	return nil, errors.WithStack(ErrUnsupportedProtoVersion)
}

func (t *MasterAgent) marshalPkt(pkt *gosnmp.SnmpPacket, err error) ([]byte, error) {
	// when err. marshal error pkt
	if err != nil {
		t.Logger.Debugf("Will marshal: %v", err)

		errFill := t.fillErrorPkt(err, pkt)
		if errFill != nil {
			return nil, err
		}

		return pkt.MarshalMsg()
	}

	out, err := pkt.MarshalMsg()
	return out, err
}

func (t *MasterAgent) getUsmSecurityParametersFromUser(username string) (*gosnmp.UsmSecurityParameters, error) {
	if username == "" {
		return &gosnmp.UsmSecurityParameters{
			Logger:                   &SnmpLoggerAdapter{t.Logger},
			AuthoritativeEngineID:    string(t.SecurityConfig.AuthoritativeEngineID.Marshal()),
			AuthoritativeEngineBoots: t.SecurityConfig.AuthoritativeEngineBoots,
			AuthoritativeEngineTime:  t.SecurityConfig.OnGetAuthoritativeEngineTime(),
		}, nil

	}
	if val := t.SecurityConfig.FindForUser(username); val != nil {
		fval := val.Copy().(*gosnmp.UsmSecurityParameters)
		var salt = make([]byte, 8)
		fval.PrivacyParameters = salt
		fval.AuthoritativeEngineID = string(t.SecurityConfig.AuthoritativeEngineID.Marshal())
		fval.AuthoritativeEngineBoots = t.SecurityConfig.AuthoritativeEngineBoots
		fval.AuthoritativeEngineTime = t.SecurityConfig.OnGetAuthoritativeEngineTime()
		fval.Logger = &SnmpLoggerAdapter{t.Logger}
		return fval, nil
	} else {
		return nil, errors.WithStack(ErrNoPermission)
	}

}

func (t *MasterAgent) fillErrorPkt(err error, io *gosnmp.SnmpPacket) error {
	io.PDUType = gosnmp.GetResponse
	if errors.Is(err, ErrNoSNMPInstance) {
		io.Error = gosnmp.NoAccess
	} else if errors.Is(err, ErrUnknownOID) {
		io.Error = gosnmp.NoSuchName
	} else if errors.Is(err, ErrUnsupportedOperation) {
		io.Error = gosnmp.ReadOnly
	} else if errors.Is(err, ErrNoPermission) {
		io.Error = gosnmp.AuthorizationError
	} else if errors.Is(err, ErrUnsupportedPacketData) {
		io.Error = gosnmp.BadValue
	} else {
		io.Error = gosnmp.GenErr
	}
	io.ErrorIndex = 0
	return nil
}

func (t *MasterAgent) ResponseForPkt(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	// Find for which SubAgent
	community := getPktContextOrCommunity(i)
	subAgent := t.findForSubAgent(community)
	if subAgent == nil {
		return i, errors.WithStack(ErrNoSNMPInstance)
	}
	return subAgent.Serve(i)
}

func (t *MasterAgent) SyncConfig() error {
	t.priv.defaultSubAgent = nil
	t.priv.communityToSubAgent = make(map[string]*SubAgent)

	for id, current := range t.SubAgents {
		t.SubAgents[id].Logger = t.Logger
		t.SubAgents[id].master = t
		if err := t.SubAgents[id].SyncConfig(); err != nil {
			return err
		}

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
			t.Logger.Debugf("communityToSubAgent: val=%v, current=%p", val, current)
			t.priv.communityToSubAgent[val] = current
		}

	}
	return nil
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
	switch i.PDUType {
	case gosnmp.GetRequest:
		return t.serveGetRequest(i)
	case gosnmp.GetNextRequest:
		return t.serveGetNextRequest(i)
	case gosnmp.SetRequest:
		return t.serveSetRequest(i)
	default:
		return nil, errors.WithStack(ErrUnsupportedOperation)
	}
}

func (t *SubAgent) checkPermission(whichPDU *PDUValueControlItem, request *gosnmp.SnmpPacket) PermissionAllowance {
	if whichPDU.OnCheckPermission == nil {
		return PermissionAllowanceAllowed
	}
	return whichPDU.OnCheckPermission(request.Version, request.PDUType, getPktContextOrCommunity(request))
}

func (t *SubAgent) getPDU(Name string, Type gosnmp.Asn1BER, Value interface{}) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:   Name,
		Type:   Type,
		Value:  Value,
		Logger: &SnmpLoggerAdapter{t.Logger},
	}
}
func (t *SubAgent) getPDUHelloVariable() gosnmp.SnmpPDU {
	// Return a variable. Usually for failture login try count.
	//   1.3.6.1.6.3.15.1.1.4.0 => http://oidref.com/1.3.6.1.6.3.15.1.1.4.0
	//   usmStatsUnknownEngineIDs
	return t.getPDU(
		"1.3.6.1.6.3.15.1.1.4.0",
		gosnmp.Counter32,
		uint32(0),
	)
}

func (t *SubAgent) getPDUNoSuchInstance(Name string) gosnmp.SnmpPDU {
	return t.getPDU(
		Name,
		gosnmp.NoSuchInstance,
		nil,
	)
}

func (t *SubAgent) getPDUNil(Name string) gosnmp.SnmpPDU {
	return t.getPDU(
		Name,
		gosnmp.Null,
		nil,
	)
}

func (t *SubAgent) getPDUObjectDescription(Name, str string) gosnmp.SnmpPDU {
	return t.getPDU(
		Name,
		gosnmp.ObjectDescription,
		str,
	)
}

func (t *SubAgent) serveGetRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	t.Logger.Debugf("before copy: %v...After copy:%v",
		i.SecurityParameters.(*gosnmp.UsmSecurityParameters),
		ret.SecurityParameters.(*gosnmp.UsmSecurityParameters))
	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
	if i.Version == gosnmp.Version3 && len(i.Variables) == 0 {
		// SNMP V3 hello packet
		mb, _ := t.master.getUsmSecurityParametersFromUser("")
		ret.SecurityParameters = mb
		ret.PDUType = gosnmp.Report
		ret.Variables = append(ret.Variables, t.getPDUHelloVariable())
		return &ret, nil
	}
	for id, varItem := range i.Variables {
		item, err := t.getForPDUValueControl(varItem.Name)
		if errors.Is(err, ErrUnknownOID) {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.NoSuchName
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNoSuchInstance(varItem.Name))
			continue
		}
		if err != nil {
			return nil, err
		}
		if t.checkPermission(item, i) != PermissionAllowanceAllowed {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.NoAccess
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNil(varItem.Name))
			continue
		}
		if item.OnGet == nil {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.ResourceUnavailable
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNil(varItem.Name))
			continue
		}
		valtoRet, err := item.OnGet()
		if err != nil {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.GenErr
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables,
				t.getPDUObjectDescription(varItem.Name, fmt.Sprintf("ERROR: %+v", err)))
			continue
		}
		ret.Variables = append(ret.Variables, gosnmp.SnmpPDU{
			Name:   varItem.Name,
			Type:   item.Type,
			Value:  valtoRet,
			Logger: &SnmpLoggerAdapter{t.Logger},
		})
		//		t.Logger.Debugf("xxx3. val=%v err=%v. ret.Variables=%v", valtoRet, err,ret.Variables)

	}

	return &ret, nil

}

func (t *SubAgent) serveGetNextRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	panic("NOTGOOD")
}

// serveSetRequest for SetReqeust.
//                 will just Return  GetResponse for Fullily SUCCESS
func (t *SubAgent) serveSetRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	ret.PDUType = gosnmp.GetResponse
	for id, varItem := range i.Variables {
		item, err := t.getForPDUValueControl(varItem.Name)
		if errors.Is(err, ErrUnknownOID) {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.NoSuchName
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNoSuchInstance(varItem.Name))
			continue
		}
		if err != nil {
			return nil, err
		}
		if t.checkPermission(item, i) != PermissionAllowanceAllowed {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.NoAccess
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNil(varItem.Name))
			continue
		}
		if item.OnSet == nil {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.ReadOnly
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNil(varItem.Name))
			continue
		}

		if err := item.OnSet(varItem.Value); err != nil {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.GenErr
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables,
				t.getPDUObjectDescription(varItem.Name, fmt.Sprintf("ERROR: %+v", err)))
			continue
		}
	}
	return &ret, nil
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
