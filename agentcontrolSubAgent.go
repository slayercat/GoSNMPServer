package GoSNMPServer

import "strings"
import "fmt"
import "sort"

import "github.com/slayercat/gosnmp"
import "github.com/pkg/errors"

type SubAgent struct {
	// ContextName selects from SNMPV3 ContextName or SNMPV1/V2c community for switch from SubAgent...
	//             set to nil means all requests will gets here(of default)

	CommunityIDs []string

	// OIDs for Read/Write actions
	OIDs []*PDUValueControlItem

	Logger ILogger

	master *MasterAgent
}

func (t *SubAgent) SyncConfig() error {
	//TODO: here
	sort.Sort(byOID(t.OIDs))
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

func (t *SubAgent) getPDUEndOfMibView(Name string) gosnmp.SnmpPDU {
	return t.getPDU(
		Name,
		gosnmp.EndOfMibView,
		nil,
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

func (t *SubAgent) getForPDUValueControlResult(item *PDUValueControlItem,
	i *gosnmp.SnmpPacket) (gosnmp.SnmpPDU, gosnmp.SNMPError) {
	if t.checkPermission(item, i) != PermissionAllowanceAllowed {
		return t.getPDUNil(item.OID), gosnmp.NoAccess
	}
	if item.OnGet == nil {
		return t.getPDUNil(item.OID), gosnmp.ResourceUnavailable
	}
	valtoRet, err := item.OnGet()
	if err != nil {
		return t.getPDUObjectDescription(item.OID, fmt.Sprintf("ERROR: %+v", err)), gosnmp.GenErr
	}
	return gosnmp.SnmpPDU{
		Name:   item.OID,
		Type:   item.Type,
		Value:  valtoRet,
		Logger: &SnmpLoggerAdapter{t.Logger},
	}, gosnmp.NoError
}

func (t *SubAgent) serveGetRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	t.Logger.Debugf("before copy: %v...After copy:%v",
		i.SecurityParameters.(*gosnmp.UsmSecurityParameters),
		ret.SecurityParameters.(*gosnmp.UsmSecurityParameters))
	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
	t.Logger.Infof("i.Version == %v len(i.Variables) = %v.", i.Version, len(i.Variables))
	if i.Version == gosnmp.Version3 && len(i.Variables) == 0 {
		// SNMP V3 hello packet
		mb, _ := t.master.getUsmSecurityParametersFromUser("")
		ret.SecurityParameters = mb
		ret.PDUType = gosnmp.Report
		ret.Variables = append(ret.Variables, t.getPDUHelloVariable())
		return &ret, nil
	}
	for id, varItem := range i.Variables {
		item, _ := t.getForPDUValueControl(varItem.Name)
		if item == nil {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.NoSuchName
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNoSuchInstance(varItem.Name))
			continue
		}

		ctl, snmperr := t.getForPDUValueControlResult(item, i)
		if snmperr != gosnmp.NoError && ret.Error != gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = uint8(id)
		}
		ret.Variables = append(ret.Variables, ctl)
	}

	return &ret, nil

}

func (t *SubAgent) serveGetNextRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	t.Logger.Debugf("before copy: %v...After copy:%v",
		i.SecurityParameters.(*gosnmp.UsmSecurityParameters),
		ret.SecurityParameters.(*gosnmp.UsmSecurityParameters))
	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
	length := len(i.Variables)
	queryForOid := i.Variables[length-1].Name
	queryForOidStriped := strings.TrimLeft(queryForOid, ".0")
	item, id := t.getForPDUValueControl(queryForOidStriped)
	t.Logger.Debugf("t.getForPDUValueControl. query_for_oid=%v item=%v id=%v", queryForOid, item, id)
	if item != nil {
		id += 1
	}
	if id >= length {
		// NOT find for the last
		ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
		return &ret, nil
	}

	if length+id > len(t.OIDs) {
		length = len(t.OIDs) - id
	}
	t.Logger.Debugf("i.Variables[id: length]. id=%v length =%v", id, length)
	for iid, item := range t.OIDs[id:length] {
		if item.NonWalkable || item.OnGet == nil {
			continue // skip non-walkable items
		}
		ctl, snmperr := t.getForPDUValueControlResult(item, i)
		if snmperr != gosnmp.NoError && ret.Error != gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = uint8(iid)
		}
		ret.Variables = append(ret.Variables, ctl)
	}

	return &ret, nil
}

// serveSetRequest for SetReqeust.
//                 will just Return  GetResponse for Fullily SUCCESS
func (t *SubAgent) serveSetRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	ret.PDUType = gosnmp.GetResponse
	for id, varItem := range i.Variables {
		item, _ := t.getForPDUValueControl(varItem.Name)
		if item == nil {
			if ret.Error == gosnmp.NoError {
				ret.Error = gosnmp.NoSuchName
				ret.ErrorIndex = uint8(id)
			}
			ret.Variables = append(ret.Variables, t.getPDUNoSuchInstance(varItem.Name))
			continue
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

func (t *SubAgent) getForPDUValueControl(oid string) (*PDUValueControlItem, int) {
	striped := strings.Trim(oid, ".")
	withDot := "." + striped
	i := sort.Search(len(t.OIDs), func(i int) bool {
		if strings.HasPrefix(t.OIDs[i].OID, ".") {
			return t.OIDs[i].OID >= withDot
		} else {
			return t.OIDs[i].OID >= striped
		}
	})
	if i < len(t.OIDs) {
		if t.OIDs[i].OID == striped || t.OIDs[i].OID == oid {
			return t.OIDs[i], i
		}
	}
	return nil, i
}
