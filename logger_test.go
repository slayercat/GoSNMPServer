package GoSNMPServer

import "testing"

func TestDiscardLogger(t *testing.T) {
	target := NewDiscardLogger()
	target.Debug("")
	target.Debugf("")
	target.Debugln("")
	target.Error("")
	target.Errorf("")
	target.Errorln("")
	target.Fatal("")
	target.Fatalf("")
	target.Fatalln("")
	target.Info("")
	target.Infof("")
	target.Infoln("")
	target.Trace("")
	target.Tracef("")
	target.Traceln("")
	target.Warn("")
	target.Warnf("")
	target.Warning("")
	target.Warningf("")
	target.Warningln("")
	target.Warnln("")

}
