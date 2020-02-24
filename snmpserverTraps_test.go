package GoSNMPServer

import (
	"net"
	"os/exec"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slayercat/gosnmp"
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
	shandle.ListenUDP("udp4", ":11611")
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
}

func TestTrapTestsSuite(t *testing.T) {
	suite.Run(t, new(TrapTests))
}
