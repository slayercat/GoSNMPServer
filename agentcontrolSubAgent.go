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

	// UserErrorMarkPacket decides if shll treat user returned error as generr
	UserErrorMarkPacket bool

	Logger ILogger

	master *MasterAgent
}

func (t *SubAgent) SyncConfig() error {
	sort.Sort(byOID(t.OIDs))
	t.Logger.Infof("Total OIDs of %v: %v", t.CommunityIDs, len(t.OIDs))
	for id, each := range t.OIDs {
		t.Logger.Infof("OIDs of %v: %v", t.CommunityIDs, each.OID)
		if id != 0 && t.OIDs[id].OID == t.OIDs[id-1].OID {
			verr := fmt.Sprintf("community %v: meet duplicate oid %v", t.CommunityIDs, each.OID)
			t.Logger.Errorf(verr)
			return errors.New(verr)
		}
	}
	return nil
}

func (t *SubAgent) Serve(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	switch i.PDUType {
	case gosnmp.GetRequest:
		return t.serveGetRequest(i)
	case gosnmp.GetNextRequest:
		return t.serveGetNextRequest(i)
	case gosnmp.GetBulkRequest:
		return t.serveGetBulkRequest(i)
	case gosnmp.SetRequest:
		return t.serveSetRequest(i)
	case gosnmp.Trap, gosnmp.SNMPv2Trap, gosnmp.InformRequest:
		return t.serveTrap(i)
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

func (t *SubAgent) getPDUOctetString(Name, str string) gosnmp.SnmpPDU {
	return t.getPDU(
		Name,
		gosnmp.OctetString,
		str,
	)
}

func (t *SubAgent) getForPDUValueControlResult(item *PDUValueControlItem,
	i *gosnmp.SnmpPacket) (pdu gosnmp.SnmpPDU, errret gosnmp.SNMPError) {
	if t.checkPermission(item, i) != PermissionAllowanceAllowed {
		return t.getPDUNil(item.OID), gosnmp.NoAccess
	}
	if item.OnGet == nil {
		return t.getPDUNil(item.OID), gosnmp.ResourceUnavailable
	}
	defer func() {
		// panic in onset
		if err := recover(); err != nil {
			pdu = t.getPDUOctetString(item.OID, fmt.Sprintf("ERROR: %+v", err))
			if t.UserErrorMarkPacket {
				errret = gosnmp.GenErr
			}
			return
		}
	}()
	valtoRet, err := item.OnGet()
	if err != nil {
		if t.UserErrorMarkPacket {
			errret = gosnmp.GenErr
		} else {
			errret = gosnmp.NoError
		}
		return t.getPDUOctetString(item.OID, fmt.Sprintf("ERROR: %+v", err)), errret
	}
	return gosnmp.SnmpPDU{
		Name:   item.OID,
		Type:   item.Type,
		Value:  valtoRet,
		Logger: &SnmpLoggerAdapter{t.Logger},
	}, gosnmp.NoError
}

func (t *SubAgent) trapForPDUValueControlResult(item *PDUValueControlItem,
	i *gosnmp.SnmpPacket, varItem gosnmp.SnmpPDU) (pdu gosnmp.SnmpPDU, errret gosnmp.SNMPError) {
	if t.checkPermission(item, i) != PermissionAllowanceAllowed {
		return t.getPDUNil(item.OID), gosnmp.NoAccess
	}
	if item.OnTrap == nil {
		return t.getPDUNil(item.OID), gosnmp.ResourceUnavailable
	}
	defer func() {
		// panic in onset
		if err := recover(); err != nil {
			pdu = t.getPDUOctetString(item.OID, fmt.Sprintf("ERROR: %+v", err))
			if t.UserErrorMarkPacket {
				errret = gosnmp.GenErr
			}
			return
		}
	}()
	isInform := false
	if i.PDUType == gosnmp.InformRequest {
		isInform = true
	}
	valtoRet, err := item.OnTrap(isInform, varItem)
	if err != nil {
		if t.UserErrorMarkPacket {
			errret = gosnmp.GenErr
		} else {
			errret = gosnmp.NoError
		}
		return t.getPDUOctetString(item.OID, fmt.Sprintf("ERROR: %+v", err)), errret
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
	t.Logger.Debugf("i.Version == %v len(i.Variables) = %v.", i.Version, len(i.Variables))
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
		if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = uint8(id)
		}
		ret.Variables = append(ret.Variables, ctl)
	}

	return &ret, nil

}

func (t *SubAgent) serveTrap(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	t.Logger.Debugf("before copy: %v...After copy:%v",
		i.SecurityParameters.(*gosnmp.UsmSecurityParameters),
		ret.SecurityParameters.(*gosnmp.UsmSecurityParameters))

	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
	t.Logger.Debugf("i.Version == %v len(i.Variables) = %v.", i.Version, len(i.Variables))
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

		ctl, snmperr := t.trapForPDUValueControlResult(item, i, varItem)
		if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = uint8(id)
		}
		ret.Variables = append(ret.Variables, ctl)
	}
	if i.PDUType == gosnmp.InformRequest {
		return &ret, nil
	} else {
		return nil, nil
	}

}

func (t *SubAgent) serveGetBulkRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
	vc := uint8(len(i.Variables))
	t.Logger.Debugf("serveGetBulkRequest (vars=%d, non-repeaters=%d, max-repetitions=%d", vc, i.NonRepeaters, i.MaxRepetitions)

	// handle Non-Repeaters
	t.Logger.Debugf("handle non-repeaters (%d)", i.NonRepeaters)
	for j := uint8(0); j < i.NonRepeaters; j++ {
		queryForOid := i.Variables[j].Name
		queryForOidStriped := strings.TrimLeft(queryForOid, ".0")
		item, id := t.getForPDUValueControl(queryForOidStriped)
		t.Logger.Debugf("(non-repeater) t.getForPDUValueControl. query_for_oid=%v item=%v id=%v", queryForOid, item, id)
		if id >= len(t.OIDs) {
			ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
			continue
		}
		item = t.OIDs[id]

		ctl, snmperr := t.getForPDUValueControlResult(item, i)
		if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = j
		}
		ret.Variables = append(ret.Variables, ctl)
	}

	t.Logger.Debugf("handle remaining (%d, max-repetitions=%d)", vc-i.NonRepeaters, i.MaxRepetitions)
	eomv := make(map[string]struct{})
	for j := uint8(0); j < i.MaxRepetitions; j++ { // loop through repetitions
		for k := i.NonRepeaters; k < vc; k++ { // loop through "repeaters"
			queryForOid := i.Variables[k].Name
			queryForOidStriped := strings.TrimLeft(queryForOid, ".0")
			item, id := t.getForPDUValueControl(queryForOidStriped)
			if item != nil {
				id += 1
			}
			nextIndex := id + int(j)
			if nextIndex >= len(t.OIDs) {
				if _, found := eomv[queryForOid]; !found {
					ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
					eomv[queryForOid] = struct{}{}
				}
				continue
			}
			item = t.OIDs[nextIndex] // repetition next
			t.Logger.Debugf("t.getForPDUValueControl. query_for_oid=%v item=%v id=%v", queryForOid, item, id)
			ctl, snmperr := t.getForPDUValueControlResult(item, i)
			if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
				ret.Error = snmperr
				ret.ErrorIndex = k
			}
			ret.Variables = append(ret.Variables, ctl)
		}
	}

	return &ret, nil
}

func (t *SubAgent) serveGetNextRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)

	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
	length := len(i.Variables)
	queryForOid := i.Variables[length-1].Name
	queryForOidStriped := strings.TrimLeft(queryForOid, ".0")
	t.Logger.Debugf("serveGetNextRequest of %v", queryForOid)
	item, id := t.getForPDUValueControl(queryForOidStriped)
	t.Logger.Debugf("t.getForPDUValueControl. query_for_oid=%v item=%v id=%v", queryForOid, item, id)
	if item != nil {
		id += 1
	}
	if id >= len(t.OIDs) {
		// NOT find for the last
		ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
		return &ret, nil
	}
	if i.MaxRepetitions != 0 {
		length = int(i.MaxRepetitions)
	}
	if length+id > len(t.OIDs) {
		length = len(t.OIDs) - id
	}
	t.Logger.Debugf("i.Variables[id: length]. id=%v length =%v. len(t.OIDs)=%v", id, length, len(t.OIDs))
	iid := id
	for {
		if iid >= len(t.OIDs) {
			break
		}
		item := t.OIDs[iid]
		if len(ret.Variables) >= length {
			break
		}

		if item.NonWalkable || item.OnGet == nil {
			t.Logger.Debugf("getnext: oid=%v. skip for non walkable", item.OID)
			iid += 1
			continue // skip non-walkable items
		}
		ctl, snmperr := t.getForPDUValueControlResult(item, i)
		if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = uint8(iid)
		}
		t.Logger.Debugf("getnext: append oid=%v. result=%v err=%v", item.OID, ctl, snmperr)
		ret.Variables = append(ret.Variables, ctl)
		iid += 1
	}

	if len(ret.Variables) == 0 {
		// NOT find for the last
		ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
	}

	return &ret, nil
}

// serveSetRequest for SetReqeust.
//
//	will just Return  GetResponse for Fullily SUCCESS
func (t *SubAgent) serveSetRequest(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	var ret gosnmp.SnmpPacket = copySnmpPacket(i)
	ret.PDUType = gosnmp.GetResponse
	ret.Variables = []gosnmp.SnmpPDU{}
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
		func() {
			defer func() {
				// panic in onset
				if err := recover(); err != nil {
					if t.UserErrorMarkPacket && ret.Error == gosnmp.NoError {
						ret.Error = gosnmp.GenErr
						ret.ErrorIndex = uint8(id)
					}
					ret.Variables = append(ret.Variables,
						t.getPDUOctetString(varItem.Name, fmt.Sprintf("ERROR: %+v", err)))
				}
			}()
			if err := item.OnSet(varItem.Value); err != nil {
				if t.UserErrorMarkPacket && ret.Error == gosnmp.NoError {
					ret.Error = gosnmp.GenErr
					ret.ErrorIndex = uint8(id)
				}
				ret.Variables = append(ret.Variables,
					t.getPDUOctetString(varItem.Name, fmt.Sprintf("ERROR: %+v", err)))
				return
			} else {
				ret.Variables = append(ret.Variables, varItem)
			}
		}()

	}
	return &ret, nil
}

func (t *SubAgent) getForPDUValueControl(oid string) (*PDUValueControlItem, int) {
	toQuery := oidToByteString(oid)
	i := sort.Search(len(t.OIDs), func(i int) bool {
		thisOid := oidToByteString(t.OIDs[i].OID)
		return thisOid >= toQuery
	})
	if i < len(t.OIDs) {
		thisOid := oidToByteString(t.OIDs[i].OID)
		if thisOid == toQuery {
			return t.OIDs[i], i
		}
	}
	return nil, i
}
