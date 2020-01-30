package GoSNMPServer

import "os"
import "github.com/sirupsen/logrus"

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
type DefaultLogger struct {
	*logrus.Logger
}

func NewDefaultLogger() ILogger {
	var log = logrus.New()
	log.Out = os.Stdout
	log.Level = logrus.TraceLevel
	return WarpLogrus(log)
}

func WarpLogrus(p *logrus.Logger) ILogger {
	return &DefaultLogger{p}
}

type DiscardLogger struct{}

func (*DiscardLogger) Debug(args ...interface{})                   {}
func (*DiscardLogger) Debugf(format string, args ...interface{})   {}
func (*DiscardLogger) Debugln(args ...interface{})                 {}
func (*DiscardLogger) Error(args ...interface{})                   {}
func (*DiscardLogger) Errorf(format string, args ...interface{})   {}
func (*DiscardLogger) Errorln(args ...interface{})                 {}
func (*DiscardLogger) Fatal(args ...interface{})                   {}
func (*DiscardLogger) Fatalf(format string, args ...interface{})   {}
func (*DiscardLogger) Fatalln(args ...interface{})                 {}
func (*DiscardLogger) Info(args ...interface{})                    {}
func (*DiscardLogger) Infof(format string, args ...interface{})    {}
func (*DiscardLogger) Infoln(args ...interface{})                  {}
func (*DiscardLogger) Trace(args ...interface{})                   {}
func (*DiscardLogger) Tracef(format string, args ...interface{})   {}
func (*DiscardLogger) Traceln(args ...interface{})                 {}
func (*DiscardLogger) Warn(args ...interface{})                    {}
func (*DiscardLogger) Warnf(format string, args ...interface{})    {}
func (*DiscardLogger) Warning(args ...interface{})                 {}
func (*DiscardLogger) Warningf(format string, args ...interface{}) {}
func (*DiscardLogger) Warningln(args ...interface{})               {}
func (*DiscardLogger) Warnln(args ...interface{})                  {}

func NewDiscardLogger() ILogger {
	return new(DiscardLogger)
}

type SnmpLoggerAdapter struct {
	ILogger
}

func (i *SnmpLoggerAdapter) Print(args ...interface{}) {
	i.ILogger.Trace(args...)
}
func (i *SnmpLoggerAdapter) Printf(format string, args ...interface{}) {
	i.ILogger.Tracef(format, args...)
}
