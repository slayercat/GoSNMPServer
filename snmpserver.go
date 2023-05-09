package GoSNMPServer

import (
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
	"net"
	_ "net/http/pprof"
	"reflect"
)

type SNMPServer struct {
	wconnStream ISnmpServerListener
	master      MasterAgent
	logger      ILogger
	poolSize    int
}

type ResForever struct {
	bytePDU []byte
	replyer IReplyer
}

func NewSNMPServer(master MasterAgent) *SNMPServer {
	ret := new(SNMPServer)
	ret.poolSize = 10
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

func (server *SNMPServer) Address() net.Addr {
	return server.wconnStream.Address()
}

func (server *SNMPServer) Shutdown() {
	server.logger.Infof("Shutdown server")
	if server.wconnStream != nil {
		server.wconnStream.Shutdown()
	}
}

func (server *SNMPServer) ServeForever(notice chan interface{}) error {
	if server.wconnStream == nil {
		return errors.New("Not Listen")
	}

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	pool, _ := ants.NewPoolWithFunc(server.poolSize, func(i interface{}) {
		resForever, ok := i.(ResForever)
		if !ok {
			return
		}
		bytePDU := resForever.bytePDU
		replyer := resForever.replyer

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
				return
			}
		}
		if err != nil {
			replyer.Shutdown()
		}
	}, ants.WithPanicHandler(func(i interface{}) {
		if e := recover(); e != nil {
			notice <- e
		}
	}))
	defer pool.Release()

	for {
		err := server.ServeNextRequest(pool)
		if err != nil {
			var operror *net.OpError
			if errors.As(err, &operror) {
				server.logger.Debugf("serveforever: break because of servenextrequest error %v", operror)
				return nil
			}

			server.logger.Errorf("serveforever: servenextrequest error %v [type %v]", err, reflect.TypeOf(err))
			return errors.Wrap(err, "servenextrequest")
		}
	}

}

func (server *SNMPServer) ServeNextRequest(pool *ants.PoolWithFunc) (err error) {
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

	bytePDU, replyer, err := server.wconnStream.NextSnmp()
	if err != nil {
		return err
	}
	resForever := ResForever{
		bytePDU: bytePDU,
		replyer: replyer,
	}
	_ = pool.Invoke(resForever)

	return nil
}

func (server *SNMPServer) SetPoolSize(poolSize int) {
	server.poolSize = poolSize
}
