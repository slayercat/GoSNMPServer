package mibImps

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"github.com/slayercat/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"log"
	"net"
	"os/exec"
	"runtime/debug"
	"testing"
)

import "github.com/Chien-W/GoSNMPServer"

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
		notice := make(chan interface{}, 0)
		go func() {
			x := <-notice
			log.Println("%+v\n", x)
			panic(string(debug.Stack()))
		}()
		err := suite.shandle.ServeForever(notice)
		if err != nil {
			panic(err)
		}
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

func (suite *SnmpServerTestSuite) TestSNMPv1UDPSnmpWalk() {
	result, err := exec.Command("snmpwalk", "-v1", "-c", "public",
		suite.getUDPPortListened().String(), "1").Output()
	if err != nil {
		suite.T().Errorf("cmd meet error: %+v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
	assert.Equal(suite.T(), len(suite.master.SubAgents[0].OIDs)+1, len(lines))
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

func (suite *SnmpServerTestSuite) TestBadSnmpV2Set() {
	// Shell Fails
	result, err := exec.Command("snmpset", "-v2c", "-c", "public",
		suite.getUDPPortListened().String(), "1.3.6.1.2.1.1.3.0", "INTEGER", "1").Output()
	assert.IsType(suite.T(), err, &exec.ExitError{})
	assert.NotEqual(suite.T(), 0, err.(*exec.ExitError).ExitCode())
	lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
	assert.Equal(suite.T(), 1, len(lines))
}

func (suite *SnmpServerTestSuite) TestBadCommunitySNMPv2UDPSnmpWalk() {
	result, err := exec.Command("snmpwalk", "-v2c", "-c", "notPublic",
		suite.getUDPPortListened().String(), "1").Output()
	assert.IsType(suite.T(), err, &exec.ExitError{})
	assert.NotEqual(suite.T(), 0, err.(*exec.ExitError).ExitCode())
	lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
	assert.Equal(suite.T(), 1, len(lines))
}

func (suite *SnmpServerTestSuite) TearDownSuite() {
	suite.shandle.Shutdown()
}

func TestSnmpServerTestSuiteSuite(t *testing.T) {
	suite.Run(t, new(SnmpServerTestSuite))
}
