package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/debug"
)
import "strings"
import "github.com/sirupsen/logrus"
import "github.com/slayercat/gosnmp"
import "github.com/Chien-W/GoSNMPServer"
import "github.com/Chien-W/GoSNMPServer/mibImps"

import "github.com/urfave/cli/v2"

func makeApp() *cli.App {
	return &cli.App{
		Name:        "gosnmpserver",
		Description: "an example server of gosnmp",
		Commands: []*cli.Command{
			{
				Name:    "RunServer",
				Aliases: []string{"run-server"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "logLevel", Value: "info"},
					&cli.StringFlag{Name: "community", Value: "public"},
					&cli.StringFlag{Name: "bindTo", Value: "127.0.0.1:161"},
					&cli.StringFlag{Name: "v3Username", Value: "testuser"},
					&cli.StringFlag{Name: "v3AuthenticationPassphrase", Value: "testauth"},
					&cli.StringFlag{Name: "v3PrivacyPassphrase", Value: "testpriv"},
				},
				Action: runServer,
			},
		},
	}
}

func main() {
	app := makeApp()
	app.Run(os.Args)
}

func runServer(c *cli.Context) error {
	logger := GoSNMPServer.NewDefaultLogger()
	switch strings.ToLower(c.String("logLevel")) {
	case "fatal":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.FatalLevel
	case "error":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.ErrorLevel
	case "info":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.InfoLevel
	case "debug":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.DebugLevel
	case "trace":
		logger.(*GoSNMPServer.DefaultLogger).Level = logrus.TraceLevel
	}
	mibImps.SetupLogger(logger)

	master := GoSNMPServer.MasterAgent{
		Logger: logger,
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
	logger.Infof("V3 Users:")
	for _, val := range master.SecurityConfig.Users {
		logger.Infof(
			"\tUserName:%v\n\t -- AuthenticationProtocol:%v\n\t -- PrivacyProtocol:%v\n\t -- AuthenticationPassphrase:%v\n\t -- PrivacyPassphrase:%v",
			val.UserName,
			val.AuthenticationProtocol,
			val.PrivacyProtocol,
			val.AuthenticationPassphrase,
			val.PrivacyPassphrase,
		)
	}
	server := GoSNMPServer.NewSNMPServer(master)
	err := server.ListenUDP("udp", c.String("bindTo"))
	if err != nil {
		logger.Errorf("Error in listen: %+v", err)
	}
	go func() {
		log.Println(http.ListenAndServe("localhost:6061", nil))
	}()
	server.SetPoolSize(100)
	notice := make(chan interface{}, 0)
	go func() {
		x := <-notice
		log.Println("%+v\n", x)
		panic(string(debug.Stack()))
	}()
	server.ServeForever(notice)
	return nil
}
