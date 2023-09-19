package GoSNMPServer

import (
	"bytes"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ServerTests struct {
	suite.Suite
	Logger ILogger

	privGetSetOIDS struct {
		val_Integer          int
		val_OctetString      string
		val_ObjectIdentifier string
		val_IPAddress        net.IP
		val_Counter32        uint
		val_Gauge32          uint
		val_TimeTicks        uint32
		val_Counter64        uint64
		val_Uinteger32       uint32
		val_OpaqueFloat      float32
		val_OpaqueDouble     float64
	}
}

func (suite *ServerTests) SetupTest() {
	logger := NewDefaultLogger()
	logger.(*DefaultLogger).Level = logrus.TraceLevel
	suite.Logger = logger
}

func (suite *ServerTests) TestNewDiscardLoggerReadyForWork() {
	master := MasterAgent{
		SubAgents: []*SubAgent{
			{},
		},
	}
	err := master.ReadyForWork()
	assert.Nil(suite.T(), err)
	assert.IsType(suite.T(), master.Logger, &DiscardLogger{})
}

func (suite *ServerTests) TestErrors() {
	getedPriv := false
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
						OID:  "1.2.4.0",
						Type: gosnmp.Integer,
						OnGet: func() (value interface{}, err error) {
							return Asn1IntegerWrap(0), nil
						},
						Document: "",
					},
					{
						OID:  "1.2.4.1",
						Type: gosnmp.IPAddress,
						OnGet: func() (value interface{}, err error) {
							return nil, errors.New("TestError")
						},
						OnSet: func(value interface{}) (err error) {
							return errors.New("TestError")
						},
						Document: "TestError",
					},
					{
						OID:  "1.2.4.2",
						Type: gosnmp.IPAddress,
						OnGet: func() (value interface{}, err error) {
							panic(errors.New("TestError"))
						},
						OnSet: func(value interface{}) (err error) {
							panic(errors.New("TestError"))
						},
						Document: "TestPanic",
					},
					{
						OID:         "1.2.4.3",
						Type:        gosnmp.IPAddress,
						NonWalkable: true,
						OnGet: func() (value interface{}, err error) {
							panic(errors.New("TestError"))
						},
						OnSet:    nil, // set will failture
						Document: "NonWalkable",
					},
					{
						OID:         "1.2.4.4",
						Type:        gosnmp.OctetString,
						NonWalkable: true,
						OnCheckPermission: func(pktVersion gosnmp.SnmpVersion, pduType gosnmp.PDUType, contextName string) PermissionAllowance {
							return PermissionAllowanceDenied
						},
						OnGet: func() (value interface{}, err error) {
							getedPriv = true
							return "B40y0&OAA6Pm", nil
						},
						OnSet: func(value interface{}) (err error) {
							getedPriv = true
							return nil
						},
						Document: "PermissionDenied",
					},
					{
						OID:  "1.2.4.5",
						Type: gosnmp.OctetString,
						OnGet: func() (value interface{}, err error) {
							return "1t&1ZZvY750j", nil
						},
						OnSet:    nil, // set will failture
						Document: "Try some Nonwalkable Items",
					},
					{
						OID:   "1.2.4.6",
						Type:  gosnmp.OctetString,
						OnGet: nil,
						OnSet: func(value interface{}) (err error) {
							return nil
						},
						Document: "SetOnly",
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
	suite.Run("SNMPWalk", func() {
		result, err := getCmdOutput("snmpwalk", "-v2c", "-c", "public",
			serverAddress.String(), "1")
		if err != nil {
			suite.T().Errorf("cmd meet error %v", err)
		}
		resultStr := string(result)
		assert.Contains(suite.T(), resultStr, "1t&1ZZvY750j")
		lines := bytes.Split(bytes.TrimSpace(result), []byte("iso"))
		assert.Equalf(suite.T(), 4+2, len(lines), "data snmpwalk gets: \n%v", string(result))
	})
	suite.Run("SNMPGetPermissionDenied", func() {
		result, err := getCmdOutput("snmpget", "-v2c", "-c", "public",
			serverAddress.String(), "1.2.4.4")
		assert.NotNil(suite.T(), err)
		resultStr := string(result)
		assert.NotContainsf(suite.T(), resultStr, "B40y0&OAA6Pm", "get result %v", string(result))
		assert.Equal(suite.T(), false, getedPriv)
	})
	suite.Run("SNMPSetPermissionDenied", func() {
		result, err := getCmdOutput("snmpset", "-v2c", "-c", "public",
			serverAddress.String(), "1.2.4.4", "i", "1")
		assert.NotNil(suite.T(), err)
		resultStr := string(result)
		assert.Equalf(suite.T(), false, getedPriv, "geted=%v", resultStr)
	})
	suite.Run("TryGetSetOnlyOID", func() {
		result, err := getCmdOutput("snmpget", "-v2c", "-c", "public",
			serverAddress.String(), "1.2.4.6")
		assert.NotNilf(suite.T(), err, "geted=%v", string(result))
	})
	suite.Run("TryAccessNonExistsOID", func() {
		result, err := getCmdOutput("snmpget", "-v2c", "-c", "public",
			serverAddress.String(), "1.2.3.4.5.6.7.8")
		assert.NotNilf(suite.T(), err, "geted=%v", string(result))

		result, err = getCmdOutput("snmpset", "-v2c", "-c", "public",
			serverAddress.String(), "1.2.3.4.5.6.7.8", "i", "1")
		assert.NotNilf(suite.T(), err, "geted=%v", string(result))
	})
	suite.Run("SNMPSet", func() {
		suite.Run("ERROR-RETURN", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.4.1", "a", "1.2.3.13")
			if err != nil {
				errmsg := string(err.(*exec.ExitError).Stderr)
				if !strings.Contains(errmsg, "Reason: (genError) A general failure occured") {
					suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
						err, errmsg, string(result))
				}
			}
		})
		suite.Run("PANIC-RETURN", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.4.2", "a", "1.2.3.13")
			if err != nil {
				errmsg := string(err.(*exec.ExitError).Stderr)
				if !strings.Contains(errmsg, "Reason: (genError) A general failure occured") {
					suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
						err, errmsg, string(result))
				}
			}
		})

		suite.Run("CouldNotSet", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.4.3", "a", "1.2.3.13")
			if err != nil {
				errmsg := string(err.(*exec.ExitError).Stderr)
				if !strings.Contains(errmsg, "(readOnly)") {
					suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
						err, errmsg, string(result))
				}
			}
		})
	})
	shandle.Shutdown()
}

func (suite *ServerTests) TestGetSetOids() {
	master := MasterAgent{
		Logger: suite.Logger,
		SecurityConfig: SecurityConfig{
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
		SubAgents: []*SubAgent{
			{
				CommunityIDs: []string{"public"},
				OIDs:         suite.getTestGetSetOIDS(),
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
	suite.Run("SNMPGetNext", func() {
		result, err := getCmdOutput("snmpgetnext", "-v2c", "-c", "public",
			serverAddress.String(), "1")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v", err)
		}
		lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
		assert.NotEqual(suite.T(), []byte{}, result, "data SNMPGetNext gets: \n%v", string(result))
		assert.Equalf(suite.T(), 1, len(lines), "data SNMPGetNext gets: \n%v", string(result))
	})
	suite.Run("SNMPWalk", func() {
		result, err := getCmdOutput("snmpwalk", "-v2c", "-c", "public",
			serverAddress.String(), "1")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v", err)
		}
		lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
		assert.Equalf(suite.T(), len(master.SubAgents[0].OIDs)+1, len(lines), "data snmpwalk gets: \n%v", string(result))
	})
	suite.Run("SNMPSet", func() {
		suite.Run("Integer", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.3.1", "i", "123")
			if err != nil {
				suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
					err, string(err.(*exec.ExitError).Stderr), string(result))
			}
		})
		suite.Run("OctetString", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.3.3", "s", "OctetString")
			if err != nil {
				suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
					err, string(err.(*exec.ExitError).Stderr), string(result))
			}
		})
		suite.Run("ObjectIdentifier", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.3.4", "o", "1.2.3.4.5")
			if err != nil {
				suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
					err, string(err.(*exec.ExitError).Stderr), string(result))
			}
			assert.Equal(suite.T(), ".1.2.3.4.5", suite.privGetSetOIDS.val_ObjectIdentifier)
		})
		suite.Run("IPAddress", func() {
			result, err := getCmdOutput("snmpset", "-v2c", "-c", "public", serverAddress.String(),
				"1.2.3.13", "a", "1.2.3.13")
			if err != nil {
				suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
					err, string(err.(*exec.ExitError).Stderr), string(result))
			}
		})

		suite.Run("ByGoSNMP", func() {
			gosnmp.Default.Target = serverAddress.IP.String()
			gosnmp.Default.Port = uint16(serverAddress.Port)
			err := gosnmp.Default.Connect()
			if err != nil {
				panic(err)
			}
			gosnmp.Default.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.Logger})
			defer gosnmp.Default.Conn.Close()
			suite.Run("Counter32", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.6",
						Type:  gosnmp.Counter32,
						Value: Asn1Counter32Wrap(123),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("Null", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.2",
						Type:  gosnmp.Null,
						Value: nil,
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("TimeTicks", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.8",
						Type:  gosnmp.TimeTicks,
						Value: Asn1TimeTicksWrap(1238),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("Counter64", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.9",
						Type:  gosnmp.Counter64,
						Value: Asn1Counter64Wrap(1239),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("Gauge32", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.7",
						Type:  gosnmp.Gauge32,
						Value: Asn1Gauge32Wrap(1239),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("Uinteger32", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.10",
						Type:  gosnmp.Uinteger32,
						Value: Asn1Uinteger32Wrap(12310),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("OpaqueFloat", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.11",
						Type:  gosnmp.OpaqueFloat,
						Value: Asn1OpaqueFloatWrap(123.11),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
			suite.Run("OpaqueDouble", func() {
				result, err := gosnmp.Default.Set([]gosnmp.SnmpPDU{
					{Name: ".1.2.3.12",
						Type:  gosnmp.OpaqueDouble,
						Value: Asn1OpaqueDoubleWrap(123.11),
					}})
				assert.Equal(suite.T(), nil, err)
				assert.Equal(suite.T(), gosnmp.SNMPError(0x0), result.Error)
			})
		})

	})
	suite.Run("SNMPBulkGet", func() {
		result, err := getCmdOutput("snmpbulkwalk", "-v2c", "-c", "public", serverAddress.String(),
			"1")
		if err != nil {
			suite.T().Errorf("cmd meet error: %+v.\nresultErr=%v\n resultout=%v",
				err, string(err.(*exec.ExitError).Stderr), string(result))
		}
		lines := bytes.Split(bytes.TrimSpace(result), []byte("\n"))
		assert.Equalf(suite.T(), len(master.SubAgents[0].OIDs)+1, len(lines), "data snmpwalk gets: \n%v", string(result))
	})
	suite.Run("SNMPWalk_UnknownUser", func() {
		result, err := getCmdOutput("snmpwalk", "-v3", "-n", "public", "-u", "UnknownUser",
			serverAddress.String(), "1")
		if err == nil {
			suite.T().Errorf("cmd not meet error! result=%v", result)
		}
	})
	shandle.Shutdown()
	<-stopWaitChain
}

func (suite *ServerTests) getTestGetSetOIDS() []*PDUValueControlItem {
	baseTestSuite := suite
	return []*PDUValueControlItem{
		{
			OID:  "1.2.3.1",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				return Asn1IntegerWrap(baseTestSuite.privGetSetOIDS.val_Integer), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1IntegerUnwrap(baseTestSuite.privGetSetOIDS.val_Integer)
				baseTestSuite.privGetSetOIDS.val_Integer = val
				return nil
			},
			Document: "TestTypeInteger",
		},
		{
			OID:  "1.2.3.2",
			Type: gosnmp.Null,
			OnGet: func() (value interface{}, err error) {
				return nil, nil
			},
			OnSet: func(value interface{}) (err error) {
				return nil
			},
			Document: "TestTypeNULL",
		},
		{
			OID:  "1.2.3.3",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				return Asn1OctetStringWrap(baseTestSuite.privGetSetOIDS.val_OctetString), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1OctetStringUnwrap(baseTestSuite.privGetSetOIDS.val_OctetString)
				baseTestSuite.privGetSetOIDS.val_OctetString = val
				return nil
			},
			Document: "TestTypeOctetString",
		},
		{
			OID:  "1.2.3.4",
			Type: gosnmp.ObjectIdentifier,
			OnGet: func() (value interface{}, err error) {
				target := baseTestSuite.privGetSetOIDS.val_ObjectIdentifier
				if !IsValidObjectIdentifier(target) {
					target = "1.2.3.4"
				}
				return Asn1ObjectIdentifierWrap(target), nil
			},
			OnSet: func(value interface{}) (err error) {
				suite.Logger.Info("set ObjectIdentifier. value=", value)
				val := Asn1ObjectIdentifierUnwrap(value)
				suite.Logger.Infof("after Asn1ObjectIdentifierUnwrap %v->%v", value, val)
				if !IsValidObjectIdentifier(val) {
					return errors.New("not a valid oid")
				}
				baseTestSuite.privGetSetOIDS.val_ObjectIdentifier = val
				return nil
			},
			Document: "TestTypeObjectIdentifier",
		},
		{
			OID:  "1.2.3.6",
			Type: gosnmp.Counter32,
			OnGet: func() (value interface{}, err error) {
				return Asn1Counter32Wrap(baseTestSuite.privGetSetOIDS.val_Counter32), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1Counter32Unwrap(baseTestSuite.privGetSetOIDS.val_Counter32)
				baseTestSuite.privGetSetOIDS.val_Counter32 = val
				return nil
			},
			Document: "TestTypeCounter32",
		},
		{
			OID:  "1.2.3.7",
			Type: gosnmp.Gauge32,
			OnGet: func() (value interface{}, err error) {
				return Asn1Gauge32Wrap(baseTestSuite.privGetSetOIDS.val_Gauge32), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1Gauge32Unwrap(baseTestSuite.privGetSetOIDS.val_Gauge32)
				baseTestSuite.privGetSetOIDS.val_Gauge32 = val
				return nil
			},
			Document: "TestTypeGauge32",
		},
		{
			OID:  "1.2.3.8",
			Type: gosnmp.TimeTicks,
			OnGet: func() (value interface{}, err error) {
				return Asn1TimeTicksWrap(baseTestSuite.privGetSetOIDS.val_TimeTicks), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1TimeTicksUnwrap(baseTestSuite.privGetSetOIDS.val_TimeTicks)
				baseTestSuite.privGetSetOIDS.val_TimeTicks = val
				return nil
			},
			Document: "TestTypeTimeTicks",
		},
		{
			OID:  "1.2.3.9",
			Type: gosnmp.Counter64,
			OnGet: func() (value interface{}, err error) {
				return Asn1Counter64Wrap(baseTestSuite.privGetSetOIDS.val_Counter64), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1Counter64Unwrap(baseTestSuite.privGetSetOIDS.val_Counter64)
				baseTestSuite.privGetSetOIDS.val_Counter64 = val
				return nil
			},
			Document: "TestTypeCounter64",
		},

		{
			OID:  "1.2.3.10",
			Type: gosnmp.Uinteger32,
			OnGet: func() (value interface{}, err error) {
				return Asn1Uinteger32Wrap(baseTestSuite.privGetSetOIDS.val_Uinteger32), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1Uinteger32Unwrap(baseTestSuite.privGetSetOIDS.val_Uinteger32)
				baseTestSuite.privGetSetOIDS.val_Uinteger32 = val
				return nil
			},
			Document: "TestTypeUinteger32",
		},
		{
			OID:  "1.2.3.11",
			Type: gosnmp.OpaqueFloat,
			OnGet: func() (value interface{}, err error) {
				return Asn1OpaqueFloatWrap(baseTestSuite.privGetSetOIDS.val_OpaqueFloat), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1OpaqueFloatUnwrap(baseTestSuite.privGetSetOIDS.val_OpaqueFloat)
				baseTestSuite.privGetSetOIDS.val_OpaqueFloat = val
				return nil
			},
			Document: "TestTypeOpaqueFloat",
		},
		{
			OID:  "1.2.3.12",
			Type: gosnmp.OpaqueDouble,
			OnGet: func() (value interface{}, err error) {
				return Asn1OpaqueDoubleWrap(baseTestSuite.privGetSetOIDS.val_OpaqueDouble), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1OpaqueDoubleUnwrap(baseTestSuite.privGetSetOIDS.val_OpaqueDouble)
				baseTestSuite.privGetSetOIDS.val_OpaqueDouble = val
				return nil
			},
			Document: "TestTypeOpaqueDouble",
		},
		{
			OID:  "1.2.3.13",
			Type: gosnmp.IPAddress,
			OnGet: func() (value interface{}, err error) {
				vat := baseTestSuite.privGetSetOIDS.val_IPAddress
				if vat == nil {
					vat = net.ParseIP("127.0.0.1")
				}
				return Asn1IPAddressWrap(vat), nil
			},
			OnSet: func(value interface{}) (err error) {
				val := Asn1IPAddressUnwrap(value)
				baseTestSuite.privGetSetOIDS.val_IPAddress = val
				return nil
			},
			Document: "TestTypeIPAddress",
		},
	}
}

func (suite *ServerTests) TearDownSuite() {
}

func TestServerTestsSuite(t *testing.T) {
	suite.Run(t, new(ServerTests))
}

func getCmdOutput(s0 string, s ...string) ([]byte, error) {
	val := exec.Command(s0, s...)
	result, err := val.Output()
	val.Wait()
	return result, err
}
