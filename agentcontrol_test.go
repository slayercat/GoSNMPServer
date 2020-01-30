package GoSNMPServer

import "testing"

import (
	"github.com/stretchr/testify/suite"
	//	"github.com/stretchr/testify/assert"
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
		SubAgents: []SubAgent{
			{
				OIDs: []PDUValueControlItem{},
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
	response, err := suite.handle.ResponseForBuffer(buf)
	if err != nil {
		suite.T().Errorf("meet error: %+v", err)
	}
	if response == nil {
		suite.T().Errorf("response shell not be nil")
	}
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

func TestResponseForBufferTestSuite(t *testing.T) {
	suite.Run(t, new(ResponseForBufferTestSuite))
}
