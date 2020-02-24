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
						OnTrap: func(isInform bool, trapdata gosnmp.SnmpPDU) (dataret *gosnmp.SnmpPDU, err error) {

							trapDataReceived = trapdata
							dataret = &gosnmp.SnmpPDU{}
							err = nil
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
}

func TestTrapTestsSuite(t *testing.T) {
	suite.Run(t, new(TrapTests))
}
