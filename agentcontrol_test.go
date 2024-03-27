package GoSNMPServer

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ResponseForBufferTestSuite struct {
	suite.Suite

	Logger ILogger

	handle *MasterAgent
}

func (suite *ResponseForBufferTestSuite) SetupTest() {
	suite.Logger = NewDefaultLogger()
	suite.handle = &MasterAgent{
		Logger: suite.Logger,
		SecurityConfig: SecurityConfig{
			AuthoritativeEngineBoots: 123,
			NoSecurity: true,
			Users: []gosnmp.UsmSecurityParameters{
				{
					UserName:                 "pippo",
					AuthenticationProtocol:   gosnmp.MD5,
					PrivacyProtocol:          gosnmp.DES,
					AuthenticationPassphrase: "pippoxxx",
					PrivacyPassphrase:        "PIPPOxxx",
				},
				{
					UserName:                 "testuser",
					AuthenticationProtocol:   gosnmp.MD5,
					PrivacyProtocol:          gosnmp.DES,
					AuthenticationPassphrase: "testauth",
					PrivacyPassphrase:        "testpriv",
				},
			},
		},
		SubAgents: []*SubAgent{
			{
				UserErrorMarkPacket: false,
				OIDs: []*PDUValueControlItem{
					{
						OID:   "1.3.6.1.2.1.43.14.1.1.6.1.5",
						Type:  gosnmp.Counter64,
						OnGet: func() (interface{}, error) { return Asn1Counter64Wrap(0x1234), nil },
					},
				},
			},
		},
	}

	err := suite.handle.ReadyForWork()
	if err != nil {
		panic(err)
	}
}

func (suite *ResponseForBufferTestSuite) TestSnmpv1GetRequest() {
	buf := suite.reqeustV1GetRequest()
	var err error

	responsebytes, err := suite.handle.ResponseForBuffer(buf)

	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if responsebytes == nil {
		suite.T().Errorf("response shell not be nil")
	}
	suite.handle.Logger.Infof("Response done. try decode")
	var handle = gosnmp.GoSNMP{}
	handle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger})
	response, err := handle.SnmpDecodePacket(responsebytes)
	if err != nil || response == nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	assert.Equal(suite.T(), "public", response.Community)
	assert.Equal(suite.T(), 1, len(response.Variables))
	assert.Equal(suite.T(), ".1.3.6.1.2.1.43.14.1.1.6.1.5", response.Variables[0].Name)
	assert.Equal(suite.T(), gosnmp.Counter64, response.Variables[0].Type)
	assert.Equal(suite.T(), uint64(0x1234), response.Variables[0].Value)
	assert.Equal(suite.T(), uint32(48), response.RequestID)
}

func (suite *ResponseForBufferTestSuite) TestSnmpv3HelloRequest() {
	buf := suite.snmpv3HelloRequest()
	var err error

	responsebytes, err := suite.handle.ResponseForBuffer(buf)

	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if responsebytes == nil {
		suite.T().Errorf("response shell not be nil")
	}
	suite.handle.Logger.Infof("Response done. try decode")
	var handle = gosnmp.GoSNMP{}
	handle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger})
	response, err := handle.SnmpDecodePacket(responsebytes)
	if err != nil || response == nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	assert.Equal(suite.T(), "", response.Community)
	assert.NotEqual(suite.T(), nil, response.SecurityParameters)
	assert.NotEqual(suite.T(), "", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineID)
	assert.Equal(suite.T(), uint32(123), response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineBoots)
	assert.NotEqual(suite.T(), 0, response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineTime)
	assert.Equal(suite.T(), 1, len(response.Variables))
	assert.Equal(suite.T(), uint32(91040642), response.MsgID)
}

func (suite *ResponseForBufferTestSuite) TestSnmpv3EncryptedRequest() {
	buf := suite.snmpv3Encrypted()
	var err error

	responsebytes, err := suite.handle.ResponseForBuffer(buf)

	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if responsebytes == nil {
		suite.T().Errorf("response shell not be nil")
	}
	suite.handle.Logger.Infof("Response done. try decode")
	var handle = gosnmp.GoSNMP{
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "pippo",
			AuthenticationProtocol:   gosnmp.MD5,
			PrivacyProtocol:          gosnmp.DES,
			AuthenticationPassphrase: "pippoxxx",
			PrivacyPassphrase:        "PIPPOxxx",
			Logger:                   gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger}),
		},
	}
	handle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger})
	response, err := handle.SnmpDecodePacket(responsebytes)
	if err != nil || response == nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	assert.Equal(suite.T(), "", response.Community)
	assert.Equal(suite.T(), gosnmp.SNMPError(0x2), response.Error)
	assert.Equal(suite.T(), uint8(0x0), response.ErrorIndex)
	assert.NotEqual(suite.T(), nil, response.SecurityParameters)
	assert.NotEqual(suite.T(), "", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineID)
	assert.Equal(suite.T(), "pippo", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).UserName)
	assert.Equal(suite.T(), uint32(123), response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineBoots)
	assert.NotEqual(suite.T(), 0, response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineTime)
	assert.Equal(suite.T(), uint32(821490645), response.MsgID)
	assert.Equal(suite.T(), gosnmp.NoSuchInstance, response.Variables[0].Type)
}

func (suite *ResponseForBufferTestSuite) TestSnmpv3GetNextRequestInitial() {
	buf := suite.snmpv3GetNextRequestInitial()
	var err error

	responsebytes, err := suite.handle.ResponseForBuffer(buf)

	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if responsebytes == nil {
		suite.T().Errorf("response shell not be nil")
	}
	suite.handle.Logger.Infof("Response done. try decode")
	var handle = gosnmp.GoSNMP{
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "testuser",
			AuthenticationProtocol:   gosnmp.MD5,
			PrivacyProtocol:          gosnmp.DES,
			AuthenticationPassphrase: "testauth",
			PrivacyPassphrase:        "testpriv",
			Logger:                   gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger}),
		},
	}
	handle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger})
	response, err := handle.SnmpDecodePacket(responsebytes)
	if err != nil || response == nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	assert.Equal(suite.T(), "", response.Community)
	assert.Equal(suite.T(), gosnmp.SNMPError(0x0), response.Error)
	assert.Equal(suite.T(), uint8(0x0), response.ErrorIndex)
	assert.NotEqual(suite.T(), nil, response.SecurityParameters)
	assert.NotEqual(suite.T(), "", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineID)
	assert.Equal(suite.T(), "testuser", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).UserName)
	assert.Equal(suite.T(), uint32(123), response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineBoots)
	assert.NotEqual(suite.T(), 0, response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineTime)
	assert.Equal(suite.T(), uint32(746966497), response.MsgID)
	assert.Equal(suite.T(), ".1.3.6.1.2.1.43.14.1.1.6.1.5", response.Variables[0].Name)
	assert.Equal(suite.T(), uint64(0x1234), response.Variables[0].Value)
}

func (suite *ResponseForBufferTestSuite) TestSnmpv3GetNextRequestEndofMib() {
	buf := suite.snmpv3GetNextRequestEndofMib()
	var err error

	responsebytes, err := suite.handle.ResponseForBuffer(buf)

	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if responsebytes == nil {
		suite.T().Errorf("response shell not be nil")
	}
	suite.handle.Logger.Infof("Response done. try decode")
	var handle = gosnmp.GoSNMP{
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "testuser",
			AuthenticationProtocol:   gosnmp.MD5,
			PrivacyProtocol:          gosnmp.DES,
			AuthenticationPassphrase: "testauth",
			PrivacyPassphrase:        "testpriv",
			Logger:                   gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger}),
		},
	}
	handle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger})
	response, err := handle.SnmpDecodePacket(responsebytes)
	if err != nil || response == nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	assert.Equal(suite.T(), "", response.Community)
	assert.Equal(suite.T(), gosnmp.SNMPError(0x0), response.Error)
	assert.Equal(suite.T(), uint8(0x0), response.ErrorIndex)
	assert.NotEqual(suite.T(), nil, response.SecurityParameters)
	assert.NotEqual(suite.T(), "", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineID)
	assert.Equal(suite.T(), "testuser", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).UserName)
	assert.Equal(suite.T(), uint32(123), response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineBoots)
	assert.NotEqual(suite.T(), 0, response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineTime)
	assert.Equal(suite.T(), uint32(746966499), response.MsgID)
	assert.Equal(suite.T(), ".1.3.6.1.2.1.43.14.1.1.6.1.5", response.Variables[0].Name)
	assert.Equal(suite.T(), gosnmp.EndOfMibView, response.Variables[0].Type)
}

func (suite *ResponseForBufferTestSuite) TestSnmpv3NotEncrypted() {
	buf := suite.snmpv3NotEncrypted()
	var err error

	responsebytes, err := suite.handle.ResponseForBuffer(buf)

	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if responsebytes == nil {
		suite.T().Errorf("response shell not be nil")
	}
	suite.handle.Logger.Infof("Response done. try decode")
	var handle = gosnmp.GoSNMP{}
	handle.Logger = gosnmp.NewLogger(&SnmpLoggerAdapter{suite.handle.Logger})
	response, err := handle.SnmpDecodePacket(responsebytes)
	if err != nil || response == nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	assert.Equal(suite.T(), "", response.Community)

	assert.NotEqual(suite.T(), nil, response.SecurityParameters)
	assert.NotEqual(suite.T(), "", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineID)
	assert.Equal(suite.T(), "testuser", response.SecurityParameters.(*gosnmp.UsmSecurityParameters).UserName)
	assert.Equal(suite.T(), uint32(123), response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineBoots)
	assert.NotEqual(suite.T(), 0, response.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineTime)
}

// Simple Network Management Protocol
//     version: version-1 (0)
//     community: public
//     data: get-request (0)
//         get-request
//             request-id: 48
//             error-status: noError (0)
//             error-index: 0
//             variable-bindings: 1 item
//                 1.3.6.1.2.1.43.14.1.1.6.1.5: Value (Null)
//                     Object Name: 1.3.6.1.2.1.43.14.1.1.6.1.5 (iso.3.6.1.2.1.43.14.1.1.6.1.5)
//                     Value (Null)

func (suite *ResponseForBufferTestSuite) reqeustV1GetRequest() []byte {
	return []byte{
		0x30, 0x2a, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
		0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x1d, 0x02,
		0x01, 0x30, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x12, 0x30, 0x10, 0x06, 0x0c, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x2b, 0x0e, 0x01, 0x01, 0x06,
		0x01, 0x05, 0x05, 0x00,
	}
}

// Simple Network Management Protocol
//     msgVersion: snmpv3 (3)
//     msgGlobalData
//         msgID: 91040642
//         msgMaxSize: 65507
//         msgFlags: 04
//         msgSecurityModel: USM (3)
//     msgAuthoritativeEngineID: <MISSING>
//     msgAuthoritativeEngineBoots: 0
//     msgAuthoritativeEngineTime: 0
//     msgUserName:
//     msgAuthenticationParameters: <MISSING>
//     msgPrivacyParameters: <MISSING>
//     msgData: plaintext (0)
//         plaintext

func (suite *ResponseForBufferTestSuite) snmpv3HelloRequest() []byte {
	return []byte{0x30, 0x52, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02,
		0x04, 0x05, 0x6d, 0x2b, 0x82, 0x02, 0x03, 0x00,
		0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
		0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
		0x04, 0x00, 0x30, 0x28, 0x04, 0x00, 0x04, 0x14,
		0x66, 0x6f, 0x72, 0x65, 0x69, 0x67, 0x6e, 0x66,
		0x6f, 0x72, 0x6d, 0x61, 0x74, 0x73, 0x2f, 0x6c,
		0x69, 0x6e, 0x75, 0x78, 0xa0, 0x0e, 0x02, 0x04,
		0x44, 0xfa, 0x16, 0xe1, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x00}
}

// Simple Network Management Protocol
//     msgVersion: snmpv3 (3)
//     msgGlobalData
//         msgID: 821490645
//         msgMaxSize: 65507
//         msgFlags: 07
//         msgSecurityModel: USM (3)
//     msgAuthoritativeEngineID: 80001f888059dc486145a26322
//         1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
//         Engine Enterprise ID: net-snmp (8072)
//         Engine ID Format: Reserved/Enterprise-specific (128): Net-SNMP Random
//         Engine ID Data: 59dc4861
//         Engine ID Data: Creation Time: Apr 14, 1988 01:15:49 中国标准时间
//     msgAuthoritativeEngineBoots: 8
//     msgAuthoritativeEngineTime: 2745
//     msgUserName: pippo
//     msgAuthenticationParameters: 19395e67894fda182414849f
//     msgPrivacyParameters: 0000000103d5321a
//     msgData: encryptedPDU (1)
//         encryptedPDU: 826ecf6443956d4c364bfc6f6ffc8ee0df000ffd0955af12…
//             Decrypted ScopedPDU: 3059040d80001f888059dc486145a263220400a04602047d…
//                 contextEngineID: 80001f888059dc486145a26322
//                     1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
//                     Engine Enterprise ID: net-snmp (8072)
//                     Engine ID Format: Reserved/Enterprise-specific (128): Net-SNMP Random
//                     Engine ID Data: 59dc4861
//                     Engine ID Data: Creation Time: Apr 14, 1988 01:15:49 中国标准时间
//                 contextName:
//                 data: get-request (0)
//                     get-request
//                         request-id: 2098071599
//                         error-status: noError (0)
//                         error-index: 0
//                         variable-bindings: 4 items
//                             1.3.6.1.2.1.1.1.0: Value (Null)
//                                 Object Name: 1.3.6.1.2.1.1.1.0 (iso.3.6.1.2.1.1.1.0)
//                                 Value (Null)
//                             1.3.6.1.2.1.1.3.0: Value (Null)
//                                 Object Name: 1.3.6.1.2.1.1.3.0 (iso.3.6.1.2.1.1.3.0)
//                                 Value (Null)
//                             1.3.6.1.2.1.4.3.0: Value (Null)
//                                 Object Name: 1.3.6.1.2.1.4.3.0 (iso.3.6.1.2.1.4.3.0)
//                                 Value (Null)
//                             1.3.6.1.2.1.4.10.0: Value (Null)
//                                 Object Name: 1.3.6.1.2.1.4.10.0 (iso.3.6.1.2.1.4.10.0)
//                                 Value (Null)
//                 [Response In: 4]

func (suite *ResponseForBufferTestSuite) snmpv3Encrypted() []byte {
	//the authPassword for all users is pippoxxx and the privPassword is PIPPOxxx.
	//pippo uses MD5 and DES
	return []byte{0x30, 0x81, 0xb1, 0x02, 0x01, 0x03, 0x30, 0x11,
		0x02, 0x04, 0x30, 0xf6, 0xf3, 0xd5, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
		0x03, 0x04, 0x37, 0x30, 0x35, 0x04, 0x0d, 0x80,
		0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61,
		0x45, 0xa2, 0x63, 0x22, 0x02, 0x01, 0x08, 0x02,
		0x02, 0x0a, 0xb9, 0x04, 0x05, 0x70, 0x69, 0x70,
		0x70, 0x6f, 0x04, 0x0c, 0x19, 0x39, 0x5e, 0x67,
		0x89, 0x4f, 0xda, 0x18, 0x24, 0x14, 0x84, 0x9f,
		0x04, 0x08, 0x00, 0x00, 0x00, 0x01, 0x03, 0xd5,
		0x32, 0x1a, 0x04, 0x60, 0x82, 0x6e, 0xcf, 0x64,
		0x43, 0x95, 0x6d, 0x4c, 0x36, 0x4b, 0xfc, 0x6f,
		0x6f, 0xfc, 0x8e, 0xe0, 0xdf, 0x00, 0x0f, 0xfd,
		0x09, 0x55, 0xaf, 0x12, 0xd2, 0xc0, 0xf3, 0xc6,
		0x0f, 0xad, 0xea, 0x41, 0x7d, 0x2b, 0xb8, 0x0c,
		0x0b, 0x2c, 0x1f, 0xa7, 0xa4, 0x6c, 0xe4, 0x4f,
		0x9f, 0x16, 0xe1, 0x5e, 0xe8, 0x30, 0xa4, 0x98,
		0x81, 0xf6, 0x0e, 0xcf, 0xa7, 0x57, 0xd2, 0xf0,
		0x40, 0x00, 0xeb, 0x39, 0xa9, 0x40, 0x58, 0x12,
		0x1d, 0x88, 0xca, 0x20, 0xee, 0xef, 0x4e, 0x6b,
		0xf0, 0x67, 0x84, 0xc6, 0x7c, 0x15, 0xf1, 0x44,
		0x91, 0x5d, 0x9b, 0xc2, 0xc6, 0xa0, 0x46, 0x1d,
		0xa9, 0x2a, 0x4a, 0xbe}
}

// Simple Network Management Protocol
//     msgVersion: snmpv3 (3)
//     msgGlobalData
//         msgID: 318530550
//         msgMaxSize: 65507
//         msgFlags: 04
//             .... .1.. = Reportable: Set
//             .... ..0. = Encrypted: Not set
//             .... ...0 = Authenticated: Not set
//         msgSecurityModel: USM (3)
//     msgAuthoritativeEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
//     msgAuthoritativeEngineBoots: 1
//     msgAuthoritativeEngineTime: 173735
//     msgUserName: testuser
//     msgAuthenticationParameters: <MISSING>
//     msgPrivacyParameters: <MISSING>
//     msgData: plaintext (0)
//         plaintext
//             contextEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
//             contextName: public
//             data: get-request (0)
//                 get-request
//                     request-id: 1981244075
//                     error-status: noError (0)
//                     error-index: 0
//                     variable-bindings: 1 item
//                         1.3.6.1.2.1.43.14.1.1.6.1.5: Value (Null)
//                             Object Name: 1.3.6.1.2.1.43.14.1.1.6.1.5 (iso.3.6.1.2.1.43.14.1.1.6.1.5)
//                             Value (Null)

func (suite *ResponseForBufferTestSuite) snmpv3NotEncrypted() []byte {
	return []byte{
		0x30, 0x81, 0x90, 0x02, 0x01, 0x03, 0x30, 0x11,
		0x02, 0x04, 0x12, 0xfc, 0x63, 0xf6, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01,
		0x03, 0x04, 0x32, 0x30, 0x30, 0x04, 0x18, 0x80,
		0x00, 0x4f, 0xb8, 0x05, 0x44, 0x45, 0x53, 0x4b,
		0x54, 0x4f, 0x50, 0x2d, 0x4a, 0x37, 0x32, 0x53,
		0x32, 0x45, 0x34, 0x3a, 0xb6, 0x3b, 0xc8, 0x02,
		0x01, 0x01, 0x02, 0x03, 0x02, 0xa6, 0xa7, 0x04,
		0x08, 0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65,
		0x72, 0x04, 0x00, 0x04, 0x00, 0x30, 0x44, 0x04,
		0x18, 0x80, 0x00, 0x4f, 0xb8, 0x05, 0x44, 0x45,
		0x53, 0x4b, 0x54, 0x4f, 0x50, 0x2d, 0x4a, 0x37,
		0x32, 0x53, 0x32, 0x45, 0x34, 0x3a, 0xb6, 0x3b,
		0xc8, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
		0x63, 0xa0, 0x20, 0x02, 0x04, 0x76, 0x17, 0x62,
		0xab, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
		0x12, 0x30, 0x10, 0x06, 0x0c, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x2b, 0x0e, 0x01, 0x01, 0x06, 0x01,
		0x05, 0x05, 0x00,
	}
}

// Simple Network Management Protocol   testuser - md5 - testauth - des - testpriv
//     msgVersion: snmpv3 (3)
//     msgGlobalData
//         msgID: 746966497
//         msgMaxSize: 65507
//         msgFlags: 07
//             .... .1.. = Reportable: Set
//             .... ..1. = Encrypted: Set
//             .... ...1 = Authenticated: Set
//         msgSecurityModel: USM (3)
//     msgAuthoritativeEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
//         1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
//         Engine Enterprise ID: pysnmp (20408)
//         Engine ID Format: Octets, administratively assigned (5)
//         Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8
//     msgAuthoritativeEngineBoots: 1
//     msgAuthoritativeEngineTime: 521149
//     msgUserName: testuser
//     msgAuthenticationParameters: d205f94f4e3e3c1c4e2bd47b
//     msgPrivacyParameters: 0000000142ba8d29
//     msgData: encryptedPDU (1)
//         encryptedPDU: 3f0e912ddab4e615aad49b52b799c3bf58cec0102bec1e64…
//             Decrypted ScopedPDU: 3039041880004fb8054445534b544f502d4a373253324534…
//                 contextEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
//                     1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
//                     Engine Enterprise ID: pysnmp (20408)
//                     Engine ID Format: Octets, administratively assigned (5)
//                     Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8
//                 contextName: public
//                 data: get-next-request (1)
//                     get-next-request
//                         request-id: 1781420923
//                         error-status: noError (0)
//                         error-index: 0
//                         variable-bindings: 1 item
//                             itu-t.1 (0.1): Value (Null)
//                                 Object Name: 0.1 (itu-t.1)
//                                 Value (Null)

func (suite *ResponseForBufferTestSuite) snmpv3GetNextRequestInitial() []byte {
	return []byte{
		0x30, 0x81, 0xa0, 0x02, 0x01, 0x03, 0x30, 0x11,
		0x02, 0x04, 0x2c, 0x85, 0xcd, 0xe1, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
		0x03, 0x04, 0x46, 0x30, 0x44, 0x04, 0x18, 0x80,
		0x00, 0x4f, 0xb8, 0x05, 0x44, 0x45, 0x53, 0x4b,
		0x54, 0x4f, 0x50, 0x2d, 0x4a, 0x37, 0x32, 0x53,
		0x32, 0x45, 0x34, 0x3a, 0xb6, 0x3b, 0xc8, 0x02,
		0x01, 0x01, 0x02, 0x03, 0x07, 0xf3, 0xbd, 0x04,
		0x08, 0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65,
		0x72, 0x04, 0x0c, 0xd2, 0x05, 0xf9, 0x4f, 0x4e,
		0x3e, 0x3c, 0x1c, 0x4e, 0x2b, 0xd4, 0x7b, 0x04,
		0x08, 0x00, 0x00, 0x00, 0x01, 0x42, 0xba, 0x8d,
		0x29, 0x04, 0x40, 0x3f, 0x0e, 0x91, 0x2d, 0xda,
		0xb4, 0xe6, 0x15, 0xaa, 0xd4, 0x9b, 0x52, 0xb7,
		0x99, 0xc3, 0xbf, 0x58, 0xce, 0xc0, 0x10, 0x2b,
		0xec, 0x1e, 0x64, 0x77, 0x8e, 0xe3, 0x48, 0xa2,
		0x04, 0x8b, 0x12, 0xac, 0x5e, 0x10, 0x45, 0xda,
		0xf6, 0x00, 0xbc, 0xd3, 0xa6, 0x4f, 0x85, 0x4d,
		0xe6, 0x50, 0x47, 0x90, 0xc7, 0xf0, 0x33, 0xbc,
		0x9e, 0x59, 0xde, 0x75, 0x34, 0x79, 0xf5, 0x38,
		0xe7, 0xfc, 0xfe,
	}
}

// Simple Network Management Protocol  testuser - md5 - testauth - des - testpriv
//     msgVersion: snmpv3 (3)
//     msgGlobalData
//         msgID: 746966499
//         msgMaxSize: 65507
//         msgFlags: 07
//             .... .1.. = Reportable: Set
//             .... ..1. = Encrypted: Set
//             .... ...1 = Authenticated: Set
//         msgSecurityModel: USM (3)
//     msgAuthoritativeEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
//         1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
//         Engine Enterprise ID: pysnmp (20408)
//         Engine ID Format: Octets, administratively assigned (5)
//         Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8
//     msgAuthoritativeEngineBoots: 1
//     msgAuthoritativeEngineTime: 521149
//     msgUserName: testuser
//     msgAuthenticationParameters: 001d8c7761ccf182f438faaf
//     msgPrivacyParameters: 0000000142ba8d2a
//     msgData: encryptedPDU (1)
//         encryptedPDU: da003a2e233c7e73f3cfa9082677f91707932f13adceffb9…
//             Decrypted ScopedPDU: 3044041880004fb8054445534b544f502d4a373253324534…
//                 contextEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
//                     1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
//                     Engine Enterprise ID: pysnmp (20408)
//                     Engine ID Format: Octets, administratively assigned (5)
//                     Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8
//                 contextName: public
//                 data: get-next-request (1)
//                     get-next-request
//                         request-id: 1781420925
//                         error-status: noError (0)
//                         error-index: 0
//                         variable-bindings: 1 item
//                             1.3.6.1.2.1.43.14.1.1.6.1.5: Value (Null)
//                                 Object Name: 1.3.6.1.2.1.43.14.1.1.6.1.5 (iso.3.6.1.2.1.43.14.1.1.6.1.5)
//                                 Value (Null)

func (suite *ResponseForBufferTestSuite) snmpv3GetNextRequestEndofMib() []byte {
	return []byte{
		0x30, 0x81, 0xa8, 0x02, 0x01, 0x03, 0x30, 0x11,
		0x02, 0x04, 0x2c, 0x85, 0xcd, 0xe3, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
		0x03, 0x04, 0x46, 0x30, 0x44, 0x04, 0x18, 0x80,
		0x00, 0x4f, 0xb8, 0x05, 0x44, 0x45, 0x53, 0x4b,
		0x54, 0x4f, 0x50, 0x2d, 0x4a, 0x37, 0x32, 0x53,
		0x32, 0x45, 0x34, 0x3a, 0xb6, 0x3b, 0xc8, 0x02,
		0x01, 0x01, 0x02, 0x03, 0x07, 0xf3, 0xbd, 0x04,
		0x08, 0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65,
		0x72, 0x04, 0x0c, 0x00, 0x1d, 0x8c, 0x77, 0x61,
		0xcc, 0xf1, 0x82, 0xf4, 0x38, 0xfa, 0xaf, 0x04,
		0x08, 0x00, 0x00, 0x00, 0x01, 0x42, 0xba, 0x8d,
		0x2a, 0x04, 0x48, 0xda, 0x00, 0x3a, 0x2e, 0x23,
		0x3c, 0x7e, 0x73, 0xf3, 0xcf, 0xa9, 0x08, 0x26,
		0x77, 0xf9, 0x17, 0x07, 0x93, 0x2f, 0x13, 0xad,
		0xce, 0xff, 0xb9, 0x9b, 0x7b, 0x62, 0xdb, 0x1e,
		0x60, 0x74, 0xbc, 0x60, 0xb2, 0xc2, 0xce, 0x56,
		0x8d, 0x32, 0x1b, 0xd1, 0xd0, 0x8d, 0x39, 0xfb,
		0x4e, 0xd1, 0xed, 0x68, 0x8b, 0x1f, 0xd6, 0xbf,
		0xc1, 0xa3, 0x87, 0x8b, 0xb8, 0x46, 0x32, 0x4b,
		0x67, 0x17, 0x5b, 0xf5, 0x26, 0x5b, 0x41, 0xe1,
		0x79, 0x3a, 0x93,
	}
}

func TestResponseForBufferTestSuite(t *testing.T) {
	suite.Run(t, new(ResponseForBufferTestSuite))
}
