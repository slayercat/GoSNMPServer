package GoSNMPServer

import "os"
import "github.com/sirupsen/logrus"

// ILogger is a logger
type ILogger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Debugln(args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Errorln(args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Fatalln(args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Infoln(args ...interface{})
	Trace(args ...interface{})
	Tracef(format string, args ...interface{})
	Traceln(args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Warning(args ...interface{})
	Warningf(format string, args ...interface{})
	Warningln(args ...interface{})
	Warnln(args ...interface{})
}

//DefaultLogger is a logger warps logrus
type DefaultLogger struct {
	*logrus.Logger
}

//NewDefaultLogger makes a new DefaultLogger
func NewDefaultLogger() ILogger {
	var log = logrus.New()
	log.Out = os.Stdout
	log.Level = logrus.TraceLevel
	return WrapLogrus(log)
}

//WrapLogrus wraps a new DefaultLogger
func WrapLogrus(p *logrus.Logger) ILogger {
	return &DefaultLogger{p}
}

//DiscardLogger throws away everything
type DiscardLogger struct{}

//Debug throws away logmessage
func (*DiscardLogger) Debug(args ...interface{}) {}

//Debugf throws away logmessage
func (*DiscardLogger) Debugf(format string, args ...interface{}) {}

//Debugln throws away logmessage
func (*DiscardLogger) Debugln(args ...interface{}) {}

//Error throws away logmessage
func (*DiscardLogger) Error(args ...interface{}) {}

//Errorf throws away logmessage
func (*DiscardLogger) Errorf(format string, args ...interface{}) {}

//Errorln throws away logmessage
func (*DiscardLogger) Errorln(args ...interface{}) {}

//Fatal throws away logmessage
func (*DiscardLogger) Fatal(args ...interface{}) {}

//Fatalf throws away logmessage
func (*DiscardLogger) Fatalf(format string, args ...interface{}) {}

//Fatalln throws away logmessage
func (*DiscardLogger) Fatalln(args ...interface{}) {}

//Info throws away logmessage
func (*DiscardLogger) Info(args ...interface{}) {}

//Infof throws away logmessage
func (*DiscardLogger) Infof(format string, args ...interface{}) {}

//Infoln throws away logmessage
func (*DiscardLogger) Infoln(args ...interface{}) {}

//Trace throws away logmessage
func (*DiscardLogger) Trace(args ...interface{}) {}

//Tracef throws away logmessage
func (*DiscardLogger) Tracef(format string, args ...interface{}) {}

//Traceln throws away logmessage
func (*DiscardLogger) Traceln(args ...interface{}) {}

//Warn throws away logmessage
func (*DiscardLogger) Warn(args ...interface{}) {}

//Warnf throws away logmessage
func (*DiscardLogger) Warnf(format string, args ...interface{}) {}

//Warning throws away logmessage
func (*DiscardLogger) Warning(args ...interface{}) {}

//Warningf throws away logmessage
func (*DiscardLogger) Warningf(format string, args ...interface{}) {}

//Warningln throws away logmessage
func (*DiscardLogger) Warningln(args ...interface{}) {}

//Warnln throws away logmessage
func (*DiscardLogger) Warnln(args ...interface{}) {}

//NewDiscardLogger makes a discard logger
func NewDiscardLogger() ILogger {
	return new(DiscardLogger)
}

// SnmpLoggerAdapter adapts a logger to gosnmp. wraps logger as trace
type SnmpLoggerAdapter struct {
	ILogger
}

//Print wraps trace
func (i *SnmpLoggerAdapter) Print(args ...interface{}) {
	i.ILogger.Trace(args...)
}

//Printf wraps trace
func (i *SnmpLoggerAdapter) Printf(format string, args ...interface{}) {
	i.ILogger.Tracef(format, args...)
}
