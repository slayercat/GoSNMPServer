package GoSNMPServer

import (
	"fmt"
	"net"
)

type SNMPServer struct {
	wconn net.Listener
}

func NewSNMPServer() *SNMPServer {
	return new(SNMPServer)
}

func (server *SNMPServer) Listen(l3proto, address string) error {
	if server.wconn != nil {
		return fmt.Errorf("Already listened")
	}
	ln, err := net.Listen(l3proto, address)
	if err != nil {
		// handle error
		return err
	}
	server.wconn = ln
	return nil
}

func (server *SNMPServer) ServeForever() {
	for {
		ln := server.wconn
		_, err := ln.Accept()
		if err != nil {
			// handle error
		}

	}
}
