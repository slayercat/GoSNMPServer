package mibImps

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"github.com/slayercat/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"net"
	"os/exec"
	"testing"
)

import "github.com/slayercat/GoSNMPServer"

type SnmpServerTestSuite struct {
	suite.Suite

	Logger GoSNMPServer.ILogger

	master  *GoSNMPServer.MasterAgent
	shandle *GoSNMPServer.SNMPServer
}

func (suite *SnmpServerTestSuite) SetupTest() {
	logger := GoSNMPServer.NewDefaultLogger()
	logger.(*GoSNMPServer.DefaultLogger).Level = logrus.InfoLevel
	suite.Logger = logger
	SetupLogger(suite.Logger)
	master := GoSNMPServer.MasterAgent{
		Logger: suite.Logger,
		SecurityConfig: GoSNMPServer.SecurityConfig{
			AuthoritativeEngineBoots: 1,
			Users: []gosnmp.UsmSecurityParameters{
				{
					UserName:                 "testUser",
					AuthenticationProtocol:   gosnmp.MD5,
					PrivacyProtocol:          gosnmp.DES,
					AuthenticationPassphrase: "testAuth",
					PrivacyPassphrase:        "testPriv",
				},
			},
		},
		SubAgents: []*GoSNMPServer.SubAgent{
			{
				CommunityIDs: []string{"public"},
				OIDs:         All(),
			},
		},
	}
	suite.master = &master
	suite.shandle = GoSNMPServer.NewSNMPServer(master)
	suite.shandle.ListenUDP("udp4", ":0")
	go func() {
		err := suite.shandle.ServeForever()
		panic(err)
	}()
}

func (suite *SnmpServerTestSuite) getUDPPortListened() *net.UDPAddr {
	addr := suite.shandle.Address()
	if udpListener, ok := addr.(*net.UDPAddr); !ok {
		return nil
	} else {
		return udpListener
	}
}

func (suite *SnmpServerTestSuite) TestSNMPv2UDPSnmpWalk() {
	result, err := exec.Command("snmpwalk", "-v2c", "-c", "public",
		suite.getUDPPortListened().String(), "1").Output()
	if err != nil {
		suite.T().Errorf("cmd meet error: %+v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
	assert.Equal(suite.T(), len(suite.master.SubAgents[0].OIDs)+1, len(lines))
}

func (suite *SnmpServerTestSuite) TestSNMPv3PrivUDPSnmpWalk() {
	result, err := exec.Command("snmpwalk", "-v3",
		"-n", "public", "-u", "testUser", "-l", "authPriv",
		"-a", "md5", "-A", "testAuth", "-x", "des", "-X", "testPriv",
		suite.getUDPPortListened().String(), "1").Output()
	if err != nil {
		suite.T().Errorf("cmd meet error: %+v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
	assert.Equal(suite.T(), len(suite.master.SubAgents[0].OIDs)+1, len(lines))
}

func (suite *SnmpServerTestSuite) TearDown() {
	suite.shandle.Shutdown()
}

func TestSnmpServerTestSuiteSuite(t *testing.T) {
	suite.Run(t, new(SnmpServerTestSuite))
}
