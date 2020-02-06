package GoSNMPServer

import "github.com/pkg/errors"

type SNMPServer struct {
	wconnStream ISnmpServerListener
	master      MasterAgent
	logger      ILogger
}

func NewSNMPServer(master MasterAgent) *SNMPServer {
	ret := new(SNMPServer)
	if err := master.ReadyForWork(); err != nil {
		panic(err)
	}
	ret.master = master
	ret.logger = master.Logger
	return ret
}

func (server *SNMPServer) ListenUDP(l3proto, address string) error {
	if server.wconnStream != nil {
		return errors.New("Listened")
	}
	i, err := NewUDPListener(l3proto, address)
	if err != nil {
		return err
	}
	server.logger.Infof("ListenUDP: l3proto=%s, address=%s", l3proto, address)
	i.SetupLogger(server.logger)
	server.wconnStream = i
	return nil
}

func (server *SNMPServer) ServeForever() error {
	if server.wconnStream == nil {
		return errors.New("Not Listen")
	}

	for {
		err := server.ServeNextRequest()
		if err != nil {
			return errors.Wrap(err, "ServeNextRequest")
		}
	}
}

func (server *SNMPServer) ServeNextRequest() error {
	bytePDU, replayer, err := server.wconnStream.NextSnmp()
	if err != nil {
		return err
	}
	result, err := server.master.ResponseForBuffer(bytePDU)
	if err != nil {
		v := "with"
		if len(result) == 0 {
			v = "without"
		}
		server.logger.Warnf("ResponseForBuffer Error: %v. %s result", err, v)
	}
	if len(result) != 0 {
		if errreplay := replayer.ReplayPDU(result); errreplay != nil {
			server.logger.Errorf("Replay PDU meet err:", errreplay)
			replayer.Shutdown()
			return nil
		}
	}
	if err != nil {
		replayer.Shutdown()
	}
	return nil
}
