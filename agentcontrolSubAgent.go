package GoSNMPServer

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
)

type SubAgent struct {
	// ContextName selects from SNMPV3 ContextName or SNMPV1/V2c community for switch from SubAgent...
	//             set to nil means all requests will gets here(of default)

	CommunityIDs []string

	// OIDs for Read/Write actions
	OIDs []*PDUValueControlItem

	oidLock sync.Mutex

	// UserErrorMarkPacket decides if shll treat user returned error as generr
	UserErrorMarkPacket bool

	Logger ILogger

	master *MasterAgent
}

// LinkOIDs links OIDs in the given array for proscessing by GoSNMPServer.
func LinkOIDs(OIDs []*PDUValueControlItem) {
	if len(OIDs) < 2 {
		return
	}
	sort.Sort(byOID(OIDs))
	OIDs[0].id = 0
	for i := 1; i < len(OIDs); i++ {
		OIDs[i-1].nextPDU = OIDs[i]
		OIDs[i].id = i
	}
}

func (t *SubAgent) SyncConfig() error {

	t.oidLock.Lock()
	defer t.oidLock.Unlock()

	t.Logger.Debugf("Total OIDs of %v: %v", t.CommunityIDs, len(t.OIDs))

	for _, oid := range t.OIDs {
		if err := VerifyOid(oid.OID); err != nil {
			return err
		}
	}

	LinkOIDs(t.OIDs)

	for id, each := range t.OIDs {
		t.Logger.Debugf("  OIDs of %v: %v", t.CommunityIDs, each.OID)
		if id != 0 && t.OIDs[id].OID == t.OIDs[id-1].OID {
			return fmt.Errorf("community %v: meet duplicate oid %v", t.CommunityIDs, each.OID)
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
		Name:  Name,
		Type:  Type,
		Value: Value,
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
		Name:  item.OID,
		Type:  item.Type,
		Value: valtoRet,
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
		Name:  item.OID,
		Type:  item.Type,
		Value: valtoRet,
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
		item, before := t.getForPDUValueControl(varItem.Name, t.OIDs)
		t.Logger.Debugf("serveGetRequest: got PDU %v (%t)", item, before)
		if before && item.id > 0 && t.OIDs[item.id-1].OnDynamicSubtree != nil {
			if strings.Contains(varItem.Name, t.OIDs[item.id-1].OID) {
				t.Logger.Debugf("previous entry contains searched id, calling OnDynamicSubtree")
				oids, err := t.OIDs[item.id-1].OnDynamicSubtree()
				if err == nil {
					item, before = t.getForPDUValueControl(varItem.Name, *oids)
					t.Logger.Debugf("Got PDU: %v (%t)", item, before)
				}
			}
		}
		if item == nil || before || item.OnGet == nil {
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
		t.Logger.Debugf("append %v", ctl)
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
		item, before := t.getForPDUValueControl(varItem.Name, t.OIDs)
		if item == nil || before {
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
	searchOIDs := &t.OIDs
	for j := uint8(0); j < i.NonRepeaters; j++ {
		if j >= vc {
			t.Logger.Errorf("too few non-repeaters")
			break
		}
		queryForOid := i.Variables[j].Name
		queryForOidStripped := strings.TrimLeft(queryForOid, ".0")
		item, before := t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
		t.Logger.Debugf("(non-repeater) t.getForPDUValueControl. query_for_oid=%v item=%+v before=%t",
			queryForOid, item, before)
		if before {
			t.Logger.Debugf("got before PDU: %v (%v)", item, item.OnDynamicSubtree)
			if item.id > 0 {
				t.Logger.Debugf("compare %s with %s", (*searchOIDs)[item.id-1].OID, queryForOidStripped)
				if strings.Contains(queryForOidStripped, (*searchOIDs)[item.id-1].OID) {
					t.Logger.Debugf("previous entry contains searched id")
					item = (*searchOIDs)[item.id-1]
				} else {
					ret.Variables = append(ret.Variables, t.getPDUNoSuchInstance(queryForOid))
					continue
				}
				if item != nil && item.OnDynamicSubtree != nil {
					t.Logger.Debugf("calling OnDynamicSubtree")
					oids, err := item.OnDynamicSubtree()
					if err == nil {
						t.Logger.Debugf("setting item to item in subtree(%d)", len(*oids))
						item, before = t.getForPDUValueControl(queryForOidStripped, *oids)
						t.Logger.Debugf("got PDU: %v (%v)", item, before)
					} else {
						// no data in subtree => not found
						item = nil
					}
				}
			}
		}

		if item == nil {
			ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
			continue
		}

		if item.OnGet == nil {
			ret.Variables = append(ret.Variables, t.getPDUNoSuchInstance(queryForOid))
			continue
		}

		ctl, snmperr := t.getForPDUValueControlResult(item, i)
		if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = j
		}
		t.Logger.Debugf("appended %v", ctl)
		ret.Variables = append(ret.Variables, ctl)
	}

	t.Logger.Debugf("handle remaining (%d, max-repetitions=%d)", vc-i.NonRepeaters, i.MaxRepetitions)
	eomv := make(map[string]struct{})
	// no repeaters left
	if vc-uint8(len(ret.Variables)) == 0 {
		return &ret, nil
	}

	lastItem := &PDUValueControlItem{OID: i.Variables[vc-uint8(len(ret.Variables))-1].Name}
	jOffset := uint32(0)
	for j := uint32(0); j < i.MaxRepetitions; j++ { // loop through repetitions
		for k := i.NonRepeaters; k < vc; k++ { // loop through "repeaters"
			t.Logger.Debugf("repeater k: %v (%v)", k, vc)
			queryForOid := i.Variables[k].Name
			queryForOidStripped := strings.TrimLeft(queryForOid, ".0")
			t.Logger.Debugf("looking for %s", queryForOidStripped)
			item, before := t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
			t.Logger.Debugf("got PDU: %v (%v)", item, before)

			if !before {
				if item.OnDynamicSubtree == nil {
					item = t.NextPDU(item, 0)
				}
				for item != nil && item.OnDynamicSubtree != nil {
					t.Logger.Debugf("calling OnDynamicSubtree")
					oids, err := item.OnDynamicSubtree()
					if err == nil {
						t.Logger.Debugf("setting item to first item in subtree")
						(*oids)[len(*oids)-1].nextPDU = item.nextPDU
						searchOIDs = oids
						item = (*oids)[0]
					} else {
						item = t.nextPDU(item, 0)
					}
				}
				t.Logger.Debugf("got next PDU: %v", item)
			} else {
				t.Logger.Debugf("got before PDU: %v (%v)", item, item.OnDynamicSubtree)
				if item.id > 0 {
					t.Logger.Debugf("compare %s with %s", (*searchOIDs)[item.id-1].OID, queryForOidStripped)
					if strings.Contains(queryForOidStripped, (*searchOIDs)[item.id-1].OID) {
						t.Logger.Debugf("previous entry contains searched id")
						item = (*searchOIDs)[item.id-1]
					}
				}
				for item != nil && item.OnDynamicSubtree != nil {
					t.Logger.Debugf("calling OnDynamicSubtree")
					oids, err := item.OnDynamicSubtree()
					nextItem := item.nextPDU
					if err == nil {
						t.Logger.Debugf("setting item to item in subtree(%d)", len(*oids))
						(*oids)[len(*oids)-1].nextPDU = nextItem
						searchOIDs = oids
						item, before = t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
						t.Logger.Debugf("got PDU: %v (%v)", item, before)
						if item == nil || item.nextPDU == nextItem {
							t.Logger.Debugf("reset to t.OID: j=%d, jo=%d", j, jOffset)
							searchOIDs = &t.OIDs
						}
						if !before {
							item = t.NextPDU(item, 0)
						}
						t.Logger.Debugf("got next PDU: %v", item)
					} else {
						item = t.NextPDU(item, 0)
					}
				}
				before = false
			}

			if j > 0 {
				t.Logger.Debugf("remaining j %d jOffset %d", j, jOffset)
				item = t.NextPDU(item, int(j-jOffset)-1)
				t.Logger.Debugf("got next %d PDU: %v", int(j-jOffset), item)
				for item != nil && item.OnDynamicSubtree != nil {
					t.Logger.Debugf("calling OnDynamicSubtree")
					oids, err := item.OnDynamicSubtree()
					nextItem := item.nextPDU
					if err == nil {
						t.Logger.Debugf("setting item to item in subtree(%d)", len(*oids))
						(*oids)[len(*oids)-1].nextPDU = nextItem
						searchOIDs = oids
						jOffset = j
						item, _ = t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
						t.Logger.Debugf("got new next %d PDU: %v", int(j-jOffset), item)
						if item == nil || item.nextPDU == nextItem {
							t.Logger.Debugf("reset to t.OID")
							searchOIDs = &t.OIDs
							jOffset = 0
						}
					} else {
						item = item.nextPDU
						t.Logger.Debugf("reset to t.OID")
						searchOIDs = &t.OIDs
						jOffset = 0
					}
				}
				if item == nil {
					t.Logger.Debugf("reset to t.OID")
					searchOIDs = &t.OIDs
					jOffset = 0
				}
			}

			if item == nil {
				if _, found := eomv[queryForOid]; !found {
					ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(lastItem.OID))
					t.Logger.Debugf("vars: %v", ret.Variables)
					eomv[queryForOid] = struct{}{}
				}
				return &ret, nil
			}
			ctl, snmperr := t.getForPDUValueControlResult(item, i)
			if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
				ret.Error = snmperr
				ret.ErrorIndex = k
			}
			lastItem = item
			t.Logger.Debugf("adding %v", ctl)
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
	queryForOidStripped := strings.TrimLeft(queryForOid, ".0")
	t.Logger.Debugf("serveGetNextRequest of %v", queryForOid)
	searchOIDs := &t.OIDs
	item, before := t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
	t.Logger.Debugf("t.getForPDUValueControl. query_for_oid=%v item=%v ", queryForOid, item)
	t.Logger.Debugf("before: %v", before)
	if item == nil {
		// NOT find for the last
		ret.Variables = append(ret.Variables, t.getPDUEndOfMibView(queryForOid))
		return &ret, nil
	}
	if before && item.id > 0 {
		t.Logger.Debugf("compare %s with %s", (*searchOIDs)[item.id-1].OID, queryForOidStripped)
		if strings.Contains(queryForOidStripped, (*searchOIDs)[item.id-1].OID) {
			t.Logger.Debugf("previous entry contains searched id")
			item = t.OIDs[item.id-1]
		}
	}

	skipNext := false
	if item.OnDynamicSubtree != nil {
		oids, err := item.OnDynamicSubtree()
		nextItem := item.nextPDU
		if err == nil {
			(*oids)[len(*oids)-1].nextPDU = nextItem
			searchOIDs = oids
			t.Logger.Debugf("setting item to item in subtree(%d)", len(*oids))
			item, before = t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
			t.Logger.Debugf("got PDU: %v", item)
			if item == nil || item.nextPDU == nextItem {
				searchOIDs = &t.OIDs
			}
			if !before {
				item = t.NextPDU(item, 0)
				before = false
			}
			t.Logger.Debugf("got next PDU: %v", item)
			skipNext = true
		} else {
			item = item.nextPDU
		}
	}
	t.Logger.Debugf("i.Variables[id: length]. id=%v length =%v. len(OIDs)=%v", item.id, length, len(*searchOIDs))
	t.Logger.Debugf("before: %v", before)
	for {
		if !before {
			if !skipNext {
				item = t.NextPDU(item, 0)
			}
			if item == nil {
				break
			}
			if item.OnDynamicSubtree != nil {
				oids, err := item.OnDynamicSubtree()
				if err == nil && len(*oids) > 0 {
					t.Logger.Debugf("setting item to first item in subtree")
					searchOIDs = oids
					item = (*oids)[0]
				} else {
					item = item.nextPDU
				}
			}
		} else {
			if item.id > 0 {
				t.Logger.Debugf("compare %s with %s", (*searchOIDs)[item.id-1].OID, queryForOidStripped)
				if strings.Contains(queryForOidStripped, (*searchOIDs)[item.id-1].OID) {
					t.Logger.Debugf("previous entry contains searched id")
					item = t.OIDs[item.id-1]
				}
				if item.OnDynamicSubtree != nil {
					t.Logger.Debugf("calling dyanmic subtree")
					nextItem := item.nextPDU
					oids, err := item.OnDynamicSubtree()
					if err == nil {
						(*oids)[len(*oids)-1].nextPDU = nextItem
						searchOIDs = oids
						t.Logger.Debugf("setting item to item in subtree(%d)", len(*oids))
						item, before = t.getForPDUValueControl(queryForOidStripped, *searchOIDs)
						t.Logger.Debugf("got PDU: %v", item)
						if item == nil || item.nextPDU == nextItem {
							searchOIDs = &t.OIDs
						}
						if !before {
							item = t.NextPDU(item, 0)
							before = false
						}
						t.Logger.Debugf("got next PDU: %v", item)
					} else {
						item = item.nextPDU
					}
				}
			}
			before = false
		}

		if len(ret.Variables) >= length {
			break
		}

		if item.NonWalkable || (item.OnGet == nil && item.OnDynamicSubtree == nil) {
			t.Logger.Debugf("getnext: oid=%v. skip for non walkable", item.OID)
			continue // skip non-walkable items
		}
		ctl, snmperr := t.getForPDUValueControlResult(item, i)
		if snmperr != gosnmp.NoError && ret.Error == gosnmp.NoError {
			ret.Error = snmperr
			ret.ErrorIndex = uint8(item.id)
		}
		t.Logger.Debugf("getnext: append oid=%v. result=%v err=%v", item.OID, ctl, snmperr)
		ret.Variables = append(ret.Variables, ctl)
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
		item, before := t.getForPDUValueControl(varItem.Name, t.OIDs)
		if item == nil || before {
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

// getForPDUValueControl this function used to lookup the handler for the oid, bool on the end is to indicate if the
// given oid came before the registered oids. For example if you did an snmpwalk and gave a '1' (IE: show me everything)
// this function would return the lowest oid value and true.
func (t *SubAgent) getForPDUValueControl(oid string, oids []*PDUValueControlItem) (*PDUValueControlItem, bool) {

	t.oidLock.Lock()
	defer t.oidLock.Unlock()

	toQuery := oidToByteString(oid)
	i := sort.Search(len(oids), func(i int) bool {
		thisOid := oidToByteString(oids[i].OID)
		compareResult := compareByteString(thisOid, toQuery)
		// thisOid >= toQuery
		return compareResult == ByteStringCompareResultGreaterThen || compareResult == ByteStringCompareResultEqual
	})

	if i < len(oids) {
		// t.OIDs[i].OID == toQuery
		compareResult := compareByteString(oidToByteString(oids[i].OID), toQuery)
		switch compareResult {
		case ByteStringCompareResultEqual:
			return oids[i], false
		case ByteStringCompareResultGreaterThen:
			return oids[i], true
		}
	}

	first := i == 0
	if first && len(oids) > 0 {
		return oids[0], true
	}
	return nil, false
}

func (t *SubAgent) NextPDU(item *PDUValueControlItem, skip int) *PDUValueControlItem {
	t.oidLock.Lock()
	defer t.oidLock.Unlock()

	return t.nextPDU(item, skip)
}

func (t *SubAgent) nextPDU(item *PDUValueControlItem, skip int) *PDUValueControlItem {
	if item == nil || item.nextPDU == nil {
		return nil
	}

	if skip == 0 {
		return item.nextPDU
	}

	skip--
	return t.nextPDU(item.nextPDU, skip)

}
