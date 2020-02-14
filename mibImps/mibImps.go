package mibImps

import "github.com/slayercat/GoSNMPServer"

import "github.com/slayercat/GoSNMPServer/mibImps/dismanEventMib"
import "github.com/slayercat/GoSNMPServer/mibImps/ifMib"
import "github.com/slayercat/GoSNMPServer/mibImps/ucdMib"

func init() {
	g_Logger = GoSNMPServer.NewDiscardLogger()
}

var g_Logger GoSNMPServer.ILogger

func SetupLogger(i GoSNMPServer.ILogger) {
	g_Logger = i
	dismanEventMib.SetupLogger(i)
	ifMib.SetupLogger(i)
	ucdMib.SetupLogger(i)
}

func All() []*GoSNMPServer.PDUValueControlItem {
	toRet := []*GoSNMPServer.PDUValueControlItem{}
	toRet = append(toRet, dismanEventMib.All()...)
	toRet = append(toRet, ifMib.All()...)
	toRet = append(toRet, ucdMib.All()...)
	return toRet
}
