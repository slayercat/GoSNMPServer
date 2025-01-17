package GoSNMPServer

import (
	"net"
	"reflect"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

type SNMPServer struct {
	udpConnStream ISnmpServerListener
	tcpListener   net.Listener
	master        MasterAgent
	logger        ILogger
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

func (server *SNMPServer) Listen(l3proto, address string) error {

	if strings.EqualFold(l3proto, "udp") {
		return server.ListenUDP(l3proto, address)
	} else if strings.EqualFold(l3proto, "tcp") || strings.EqualFold(l3proto, "both") {
		err := server.ListenUDP("udp", address)
		if err != nil {
			return err
		} else {
			return server.ListenTCP(address)
		}

	} else {
		return errors.New("Unknown l3proto")
	}

}

func (server *SNMPServer) ListenTCP(address string) error {

	if server.tcpListener != nil {
		return errors.New("Listened TCP")
	}
	var err error
	list, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrap(err, "TCP Listen Error")
	}
	server.tcpListener = list
	server.logger.Infof("ListenTCP: address=%s", address)
	return nil
}

func (server *SNMPServer) ListenUDP(l3proto, address string) error {
	if server.udpConnStream != nil {
		return errors.New("Listened")
	}
	i, err := NewUDPListener(l3proto, address)
	if err != nil {
		return err
	}
	server.logger.Infof("ListenUDP: l3proto=%s, address=%s", l3proto, address)
	i.SetupLogger(server.logger)
	server.udpConnStream = i
	return nil
}

func (server *SNMPServer) Address() net.Addr {
	return server.udpConnStream.Address()
}

func (server *SNMPServer) Shutdown() {
	server.logger.Infof("Shutdown server")
	if server.udpConnStream != nil {
		server.udpConnStream.Shutdown()
	}

	if server.tcpListener != nil {
		server.tcpListener.Close()
		server.tcpListener = nil
	}

}

func (server *SNMPServer) ServeForever() error {
	if server.udpConnStream == nil {
		return errors.New("Not Listen")
	}

	if server.tcpListener != nil {
		go server.ServeForEverTCP()
	}
	for {
		err := server.ServeNextRequest()
		if err != nil {
			var opError *net.OpError
			if errors.As(err, &opError) {
				server.logger.Debugf("ServeForever: break because of serveNextRequest error %v", opError)
				return nil
			}

			server.logger.Errorf("ServeForever: ServeNextRequest error %v [type %v]", err, reflect.TypeOf(err))
			return errors.Wrap(err, "ServeNextRequest")
		}
	}
}

func (server *SNMPServer) ServeForEverTCP() error {

	for {
		conn, err := server.tcpListener.Accept()
		if err != nil {
			// Check if the error is due to closing the listener
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" && opErr.Net == "tcp" && opErr.Err == syscall.EINVAL {
				server.logger.Errorf("ServeForEverTCP: listener closing accept error %v [type %v]", err, reflect.TypeOf(err))
				break // Exit the loop
			}

			server.logger.Errorf("ServeForEverTCP:  listener accept error %v [type %v]", err, reflect.TypeOf(err))
			continue // Continue accepting other connections
		}

		go server.handleTCPConnection(conn) // Handle each connection in a new goroutine
	}
	return nil
}

func (server *SNMPServer) handleTCPConnection(conn net.Conn) (err error) {
	server.logger.Infof("tcp connection from %v", conn.RemoteAddr())
	defer conn.Close()

	for {
		var msg [4096]byte
		counts, err := conn.Read(msg[:])
		if err != nil {
			server.logger.Errorf("tcp read error: %v", err)
			break
		}
		server.logger.Infof("tcp request from %v. size=%v", conn.RemoteAddr(), counts)
		result, err := server.master.ResponseForBuffer(msg[:counts])
		if err != nil {
			server.logger.Errorf("ResponseForBuffer Error: %v. %s result", err, result)
			break
		}

		_, err = conn.Write(result)
		if err != nil {
			server.logger.Errorf("ResponseForBuffer Error: %v.", err)
			break

		}
	}
	return nil
}

func (server *SNMPServer) ServeNextRequest() (err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case error:
				err = errors.Wrap(err.(error), "ServeNextRequest fails with panic")
			default:
				err = errors.Errorf("ServeNextRequest fails with panic. err(type %v)=%v", reflect.TypeOf(err), err)
			}
			server.logger.Errorf("ServeNextRequest error: %+v", err)
			return
		}
	}()
	bytePDU, replyer, err := server.udpConnStream.NextSnmp()
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
		if errreply := replyer.ReplyPDU(result); errreply != nil {
			server.logger.Errorf("Reply PDU meet err:", errreply)
			replyer.Shutdown()
			return nil
		}
	}
	if err != nil {
		replyer.Shutdown()
	}
	return nil
}
