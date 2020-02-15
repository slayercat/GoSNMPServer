package GoSNMPServer

import (
	"testing"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"github.com/stretchr/testify/assert"
)

type ServerTests struct {
	suite.Suite
	Logger ILogger
}

func (suite *ServerTests) SetupTest() {
	logger := NewDefaultLogger()
	logger.(*DefaultLogger).Level = logrus.InfoLevel
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
	assert.IsType(suite.T(), master.Logger,&DiscardLogger{})
}

func (suite *ServerTests) TearDownSuite() {
}

func TestServerTestsSuite(t *testing.T) {
	suite.Run(t, new(ServerTests))
}
