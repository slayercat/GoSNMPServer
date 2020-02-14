GoSNMPServer
======
[![Build Status](https://travis-ci.org/slayercat/GoSNMPServer.svg?branch=master)](https://travis-ci.org/slayercat/GoSNMPServer)
[![GoDoc](https://godoc.org/github.com/slayercat/GoSNMPServer?status.png)](http://godoc.org/github.com/slayercat/GoSNMPServer)

GoSNMPServer is an SNMP server library fully written in Go. It **WILL** provides Server Get,
GetNext, GetBulk, Walk, BulkWalk, Set and Traps. It supports IPv4 and
IPv6, using __SNMPv2c__ or __SNMPv3__. Builds are tested against
linux/amd64 and linux/386.

TL;DR
-----
Build your own SNMP Server, try this:
```shell
go install github.com/slayercat/GoSNMPServer/cmd/gosnmpserver
$(go env GOPATH)/bin/gosnmpserver run-server
snmpwalk -v 3 -l authPriv  -n public -u testuser   -a md5 -A testauth -x des -X testpriv 127.0.0.1:1161 1
```

QuickStart
-----
```golang
import "github.com/slayercat/gosnmp"
import "github.com/slayercat/GoSNMPServer"
import "github.com/slayercat/GoSNMPServer/mibImps/ucdMib"
```

```golang

master := GoSNMPServer.MasterAgent{
    Logger: GoSNMPServer.NewDefaultLogger(),
    SecurityConfig: GoSNMPServer.SecurityConfig{
        AuthoritativeEngineBoots: 1,
        Users: []gosnmp.UsmSecurityParameters{
            {
                UserName:                 c.String("v3Username"),
                AuthenticationProtocol:   gosnmp.MD5,
                PrivacyProtocol:          gosnmp.DES,
                AuthenticationPassphrase: c.String("v3AuthenticationPassphrase"),
                PrivacyPassphrase:        c.String("v3PrivacyPassphrase"),
            },
        },
    },
    SubAgents: []*GoSNMPServer.SubAgent{
        {
            CommunityIDs: []string{c.String("community")},
            OIDs:         ucdMib.All(),
        },
    },
}
server := GoSNMPServer.NewSNMPServer(master)
err := server.ListenUDP("udp", "127.0.0.1:1161")
if err != nil {
    logger.Errorf("Error in listen: %+v", err)
}
server.ServeForever()
```

Thanks
-----
This library is based on **[soniah/gosnmp](https://github.com/soniah/gosnmp)** for encoder / decoders. (made a [fork](https://github.com/slayercat/gosnmp) for maintenance)
