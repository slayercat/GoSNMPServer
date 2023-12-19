package GoSNMPServer

import (
	"reflect"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/host"
)

type FuncGetAuthoritativeEngineTime func() uint32

// MasterAgent identifys software which runs on managed devices
//
//	One server (port) could ONLY have one MasterAgent
type MasterAgent struct {
	SecurityConfig SecurityConfig

	SubAgents []*SubAgent

	Logger ILogger

	priv struct {
		communityToSubAgent map[string]*SubAgent
		defaultSubAgent     *SubAgent
	}
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
	for item := range v.Users {
		if v.Users[item].UserName == name {
			return &v.Users[item]
		}
	}
	return nil
}

type SNMPEngineID struct {
	// See https://tools.ietf.org/html/rfc3411#section-5
	// 			SnmpEngineID ::= TEXTUAL-CONVENTION
	//      SYNTAX       OCTET STRING (SIZE(5..32))
	EngineIDData string
}

func (t *SNMPEngineID) Marshal() []byte {

	// msgAuthoritativeEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
	// 1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
	// Engine Enterprise ID: pysnmp (20408)
	// Engine ID Format: Octets, administratively assigned (5)
	// Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8

	var tm = []byte{
		0x80, 0x00, 0x4f, 0xb8, 0x05,
	}
	toAppend := []byte(t.EngineIDData)
	maxDefineallowed := 32 - 5
	if len(toAppend) > maxDefineallowed { //Max 32 bytes
		toAppend = toAppend[:maxDefineallowed]
	}
	tm = append(tm, toAppend...)
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
	vhandle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{t.Logger})
	mb, _ := t.getUsmSecurityParametersFromUser("")
	vhandle.SecurityParameters = mb
	request, decodeError := vhandle.SnmpDecodePacket(i)

	switch request.Version {
	case gosnmp.Version1, gosnmp.Version2c:
		return t.marshalPkt(t.ResponseForPkt(request))
		//
	case gosnmp.Version3:
		// check for initial - discover response / non Privacy Items
		if decodeError == nil && len(request.Variables) == 0 {
			val, err := t.ResponseForPkt(request)

			if val == nil {
				return t.marshalPkt(request, err)
			} else {
				return t.marshalPkt(val, err)
			}
		}
		//v3 might want for Privacy
		if request.SecurityParameters == nil {
			return nil, errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP Returns %v", decodeError)
		}
		username := t.getUserNameFromRequest(request)
		usm, err := t.getUsmSecurityParametersFromUser(username)
		if err != nil {
			return nil, err
		}
		if decodeError != nil {
			t.Logger.Debugf("v3 decode [will fail with non password] meet %v", err)
			vhandle.SecurityParameters = &gosnmp.UsmSecurityParameters{
				UserName:                 usm.UserName,
				AuthenticationProtocol:   usm.AuthenticationProtocol,
				PrivacyProtocol:          usm.PrivacyProtocol,
				AuthenticationPassphrase: usm.AuthenticationPassphrase,
				PrivacyPassphrase:        usm.PrivacyPassphrase,
				Logger:                   vhandle.Logger,
			}
			request, err = vhandle.SnmpDecodePacket(i)
			if err != nil {
				return nil, errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP Returns %v", err)
			}
		}

		val, err := t.ResponseForPkt(request)
		if val == nil {
			request.SecurityParameters = vhandle.SecurityParameters
			return t.marshalPkt(request, err)
		} else {
			securityParamters := usm
			GenKeys(securityParamters)
			GenSalt(securityParamters)
			val.SecurityParameters = securityParamters

			return t.marshalPkt(val, err)
		}
	}
	return nil, errors.WithStack(ErrUnsupportedProtoVersion)
}

func (t *MasterAgent) marshalPkt(pkt *gosnmp.SnmpPacket, err error) ([]byte, error) {
	// when err. marshal error pkt
	if pkt == nil {
		pkt = &gosnmp.SnmpPacket{}
	}
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
			Logger:                   gosnmp.NewLogger(&SnmpLoggerAdapter{t.Logger}),
			AuthoritativeEngineID:    string(t.SecurityConfig.AuthoritativeEngineID.Marshal()),
			AuthoritativeEngineBoots: t.SecurityConfig.AuthoritativeEngineBoots,
			AuthoritativeEngineTime:  t.SecurityConfig.OnGetAuthoritativeEngineTime(),
		}, nil

	}
	if val := t.SecurityConfig.FindForUser(username); val != nil {
		fval := val.Copy().(*gosnmp.UsmSecurityParameters)
		fval.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{t.Logger})
		fval.AuthoritativeEngineID = string(t.SecurityConfig.AuthoritativeEngineID.Marshal())
		fval.AuthoritativeEngineBoots = t.SecurityConfig.AuthoritativeEngineBoots
		fval.AuthoritativeEngineTime = t.SecurityConfig.OnGetAuthoritativeEngineTime()
		return fval, nil
	} else {
		return nil, errors.WithStack(ErrNoPermission)
	}

}

func (t *MasterAgent) fillErrorPkt(err error, io *gosnmp.SnmpPacket) error {
	io.PDUType = gosnmp.GetResponse
	if errors.Is(err, ErrNoSNMPInstance) {
		io.Error = gosnmp.NoAccess
	} else if errors.Is(err, ErrUnsupportedOperation) {
		io.Error = gosnmp.ResourceUnavailable
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

		if len(current.CommunityIDs) == 0 || t.SecurityConfig.NoSecurity {
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

func DefaultAuthoritativeEngineID() SNMPEngineID {
	// XXX:TODO: return random
	val, _ := host.Info()
	data := strings.Replace(val.HostID, "-", "", -1)
	return SNMPEngineID{
		EngineIDData: data,
	}
}

func DefaultGetAuthoritativeEngineTime() uint32 {
	val, err := host.Uptime()
	if err != nil {
		return uint32(time.Now().Unix())
	}
	return uint32(val)
}
