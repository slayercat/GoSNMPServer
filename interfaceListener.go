package GoSNMPServer

import  (
	"net"
	"sync"

	"github.com/pkg/errors"
)

type ISnmpServerListener interface {
	SetupLogger(ILogger)
	Address() net.Addr
	NextSnmp() (snmpbytes []byte, replyer IReplyer, err error)
	Shutdown()
}

type IReplyer interface {
	ReplyPDU([]byte) error
	Shutdown()
}

type UDPListener struct {
	conn   *net.UDPConn
	mutex  sync.RWMutex
	logger ILogger
}

func NewUDPListener(l3proto, address string) (ISnmpServerListener, error) {
	ret := new(UDPListener)
	ret.logger = NewDiscardLogger()
	udpaddr, err := net.ResolveUDPAddr(l3proto, address)
	if err != nil {
		return nil, errors.Wrap(err, "ResolveUDPAddr Error")
	}
	conn, err := net.ListenUDP(l3proto, udpaddr)
	if err != nil {
		return nil, errors.Wrap(err, "UDP Listen Error")
	}
	ret.conn = conn
	return ret, nil
}

func (udp *UDPListener) SetupLogger(i ILogger) {
	udp.logger = i
}
func (udp *UDPListener) Address() net.Addr {
	return udp.conn.LocalAddr()
}

func (udp *UDPListener) NextSnmp() ([]byte, IReplyer, error) {
	udp.mutex.RLock()
	conn := udp.conn
	udp.mutex.RUnlock()

	if conn == nil {
		return nil, nil, errors.New("Connection Not Listen")
	}
	var msg [4096]byte
	counts, udpAddr, err := conn.ReadFromUDP(msg[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "UDP Read Error")
	}
	udp.logger.Infof("udp request from %v. size=%v", udpAddr, counts)
	return msg[:counts], &UDPReplyer{udpAddr, conn}, nil
}

func (udp *UDPListener) Shutdown() {
	udp.mutex.Lock()
	defer udp.mutex.Unlock()

	if udp.conn != nil {
		udp.conn.Close()
		udp.conn = nil
	}
}

type UDPReplyer struct {
	target *net.UDPAddr
	conn   *net.UDPConn
}

func (r *UDPReplyer) ReplyPDU(i []byte) error {
	conn := r.conn
	_, err := conn.WriteToUDP(i, r.target)
	if err != nil {
		return errors.Wrap(err, "WriteToUDP")
	}
	return nil
}

func (r *UDPReplyer) Shutdown() {}
