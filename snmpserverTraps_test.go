package GoSNMPServer

import (
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TrapTests struct {
	suite.Suite
	Logger ILogger
}

func (suite *TrapTests) SetupTest() {
	logger := NewDefaultLogger()
	logger.(*DefaultLogger).Level = logrus.TraceLevel
	suite.Logger = logger
}

func (suite *TrapTests) TestTraps() {
	var trapDataReceived gosnmp.SnmpPDU
	var waiterReadyToWork = make(chan int, 1)
	master := MasterAgent{
		Logger: suite.Logger,
		SecurityConfig: SecurityConfig{
			AuthoritativeEngineBoots: 1,
			NoSecurity:               true,
			Users: []gosnmp.UsmSecurityParameters{
				{
					UserName:                 "user",
					AuthenticationProtocol:   gosnmp.SHA,
					AuthenticationPassphrase: "password",
					PrivacyProtocol:          gosnmp.AES,
					PrivacyPassphrase:        "password",
				},
			},
		},
		SubAgents: []*SubAgent{
			{
				CommunityIDs: []string{"public"},
				OIDs: []*PDUValueControlItem{

					{
						OID:  "1.2.4.1",
						Type: gosnmp.OctetString,
						OnTrap: func(isInform bool, trapdata gosnmp.SnmpPDU) (dataret interface{}, err error) {

							trapDataReceived = trapdata
							dataret = nil
							err = nil
							if isInform {
								//return something
								dataret = Asn1OctetStringWrap("testInformReturn")
							}
							waiterReadyToWork <- 1
							return
						},
						Document: "Trap",
					},
				},
			},
		},
	}
	shandle := NewSNMPServer(master)
	shandle.ListenUDP("udp4", ":0")
	var stopWaitChain = make(chan int)
	go func() {
		err := shandle.ServeForever()
		if err != nil {
			suite.Logger.Errorf("error in ServeForever: %v", err)
		} else {
			suite.Logger.Info("ServeForever Stoped.")
		}
		stopWaitChain <- 1

	}()
	serverAddress := shandle.Address().(*net.UDPAddr)
	suite.Run("Trapv2OctetString", func() {
		result, err := getCmdOutput("snmptrap", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.1", "1.2.4.1", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		_ = <-waiterReadyToWork
		data := Asn1OctetStringUnwrap(trapDataReceived.Value)
		assert.Equal(suite.T(), "1.2.3.13", data)
	})
	suite.Run("Trapv1OctetString", func() {
		result, err := getCmdOutput("snmptrap", "-v", "1", "-c", "public", serverAddress.String(),
			"", "", "6", "17", "", "1.2.4.1", "s", "v1Test")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		_ = <-waiterReadyToWork
		data := Asn1OctetStringUnwrap(trapDataReceived.Value)
		assert.Equal(suite.T(), "v1Test", data)
	})
	suite.Run("Inform", func() {
		result, err := getCmdOutput("snmpinform", "-D", "ALL", "-LE", "d", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.1", "1.2.4.1", "s", "inform")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		_ = <-waiterReadyToWork
		data := Asn1OctetStringUnwrap(trapDataReceived.Value)
		assert.Equal(suite.T(), "inform", data)
		assert.Equal(suite.T(), "", string(result))
	})
	suite.Run("Trapv3OctetString", func() {
		result, err := getCmdOutput("snmpinform", "-v3", "-n", "public",
			"-l", "authPriv", "-u", "user",
			"-a", "SHA", "-A", "password",
			"-x", "AES", "-X", "password",
			serverAddress.String(),
			"", "1.2.4.1", "1.2.4.1", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		_ = <-waiterReadyToWork
		data := Asn1OctetStringUnwrap(trapDataReceived.Value)
		assert.Equal(suite.T(), "1.2.3.13", data)
	})
	suite.Run("Trap V3", func() {

		// refer: https://github.com/soniah/gosnmp/issues/145
		client := &gosnmp.GoSNMP{
			Target:        "127.0.0.1",
			Port:          uint16(serverAddress.Port),
			Version:       gosnmp.Version3,
			Timeout:       time.Duration(30) * time.Second,
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      gosnmp.AuthPriv,
			//ContextName:   "public", //MUST have
			Logger: gosnmp.NewLogger(&SnmpLoggerAdapter{suite.Logger}),
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 "user",
				AuthenticationProtocol:   gosnmp.SHA,
				AuthenticationPassphrase: "password",
				PrivacyProtocol:          gosnmp.AES,
				PrivacyPassphrase:        "password",
				Logger:                   gosnmp.NewLogger(&SnmpLoggerAdapter{suite.Logger}),
			},
		}

		if err := client.Connect(); err != nil {
			panic(err)
		}
		defer client.Conn.Close()

		trap := gosnmp.SnmpTrap{
			Variables: []gosnmp.SnmpPDU{
				gosnmp.SnmpPDU{
					Name:  ".1.2.4.1",
					Type:  gosnmp.OctetString,
					Value: ".1.3.6.1.6.3.1.1.5.1",
				},
			},
		}

		if _, err := client.SendTrap(trap); err != nil {
			panic(err)
		}
		_ = <-waiterReadyToWork
		data := Asn1OctetStringUnwrap(trapDataReceived.Value)
		assert.Equal(suite.T(), ".1.3.6.1.6.3.1.1.5.1", data)
	})
	shandle.Shutdown()
}

func (suite *TrapTests) TestErrorTraps() {
	var waiterReadyToWork = make(chan int, 1)
	master := MasterAgent{
		Logger: suite.Logger,
		SecurityConfig: SecurityConfig{
			AuthoritativeEngineBoots: 1,
			Users:                    []gosnmp.UsmSecurityParameters{},
		},
		SubAgents: []*SubAgent{
			{
				CommunityIDs: []string{"public"},
				OIDs: []*PDUValueControlItem{

					{
						OID:  "1.2.4.1",
						Type: gosnmp.OctetString,
						OnTrap: func(isInform bool, trapdata gosnmp.SnmpPDU) (dataret interface{}, err error) {
							err = errors.New("OnTrap errors")
							waiterReadyToWork <- 1
							return
						},
						Document: "Trap",
					},
					{
						OID:  "1.2.4.2",
						Type: gosnmp.OctetString,
						OnCheckPermission: func(pktVersion gosnmp.SnmpVersion, pduType gosnmp.PDUType, contextName string) PermissionAllowance {
							waiterReadyToWork <- 2
							return PermissionAllowanceDenied
						},
						OnTrap: func(isInform bool, trapdata gosnmp.SnmpPDU) (dataret interface{}, err error) {
							return
						},
						Document: "Trap",
					},
					{
						OID:  "1.2.4.3",
						Type: gosnmp.OctetString,
						OnTrap: func(isInform bool, trapdata gosnmp.SnmpPDU) (dataret interface{}, err error) {
							waiterReadyToWork <- 3
							panic("panic")
						},
						Document: "Trap",
					},
				},
			},
		},
	}
	shandle := NewSNMPServer(master)
	shandle.ListenUDP("udp4", ":0")
	var stopWaitChain = make(chan int)
	go func() {
		err := shandle.ServeForever()
		if err != nil {
			suite.Logger.Errorf("error in ServeForever: %v", err)
		} else {
			suite.Logger.Info("ServeForever Stoped.")
		}
		stopWaitChain <- 1

	}()
	serverAddress := shandle.Address().(*net.UDPAddr)
	suite.Run("TestFail", func() {
		result, err := getCmdOutput("snmptrap", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.1", "1.2.4.1", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		rr := <-waiterReadyToWork
		assert.Equal(suite.T(), 1, rr)
	})
	suite.Run("TestPermission", func() {

		result, err := getCmdOutput("snmptrap", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.2", "1.2.4.2", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		rr := <-waiterReadyToWork
		assert.Equal(suite.T(), 2, rr)
	})
	suite.Run("TestPanic", func() {
		result, err := getCmdOutput("snmptrap", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.3", "1.2.4.3", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		rr := <-waiterReadyToWork
		assert.Equal(suite.T(), 3, rr)
	})
	suite.Run("TestFail-UserErrorMarkPacket", func() {
		master.SubAgents[0].UserErrorMarkPacket = true
		result, err := getCmdOutput("snmptrap", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.2", "1.2.4.1", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		rr := <-waiterReadyToWork
		assert.Equal(suite.T(), 1, rr)
		master.SubAgents[0].UserErrorMarkPacket = false
	})
	suite.Run("TestPanic-UserErrorMarkPacket", func() {
		master.SubAgents[0].UserErrorMarkPacket = true
		result, err := getCmdOutput("snmptrap", "-v2c", "-c", "public", serverAddress.String(),
			"", "1.2.4.3", "1.2.4.3", "s", "1.2.3.13")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		rr := <-waiterReadyToWork
		assert.Equal(suite.T(), 3, rr)
		master.SubAgents[0].UserErrorMarkPacket = false
	})
	shandle.Shutdown()
}

func TestTrapTestsSuite(t *testing.T) {
	suite.Run(t, new(TrapTests))
}
