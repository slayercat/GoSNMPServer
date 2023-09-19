/*
GoSNMPServer is an SNMP server library fully written in Go. It **WILL** provides Server Get,
GetNext, GetBulk, Walk, BulkWalk, Set and Traps. It supports IPv4 and
IPv6, using __SNMPv2c__ or __SNMPv3__. Builds are tested against
linux/amd64 and linux/386.

Build your own SNMP Server, try this:

	go install github.com/slayercat/GoSNMPServer/cmd/gosnmpserver
	$(go env GOPATH)/bin/gosnmpserver run-server
	snmpwalk -v 3 -l authPriv  -n public -u testuser   -a md5 -A testauth -x des -X testpriv 127.0.0.1:1161 1

Some Code Here:

	import "github.com/gosnmp/gosnmp"
	import "github.com/slayercat/GoSNMPServer"
	import "github.com/slayercat/GoSNMPServer/mibImps"


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
				OIDs:         mibImps.All(),
			},
		},
	}
	server := GoSNMPServer.NewSNMPServer(master)
	err := server.ListenUDP("udp", "127.0.0.1:1161")
	if err != nil {
		logger.Errorf("Error in listen: %+v", err)
	}
	server.ServeForever()

# Serve your own oids

This library provides some common oid for use.  See godoc for details.

See https://github.com/slayercat/GoSNMPServer/tree/master/mibImps for code.

Append `GoSNMPServer.PDUValueControlItem` to your SubAgent OIDS:

	{
		OID:      fmt.Sprintf("1.3.6.1.2.1.2.2.1.1.%d", ifIndex),
		Type:     gosnmp.Integer,
		OnGet:    func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(ifIndex), nil },
		Document: "ifIndex",
	},
*/
package GoSNMPServer
