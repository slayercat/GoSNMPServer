package GoSNMPServer

import "github.com/pkg/errors"

var ErrUnsupportedProtoVersion = errors.New("ErrUnsupportedProtoVersion")
var ErrNoSNMPInstance = errors.New("ErrNoSNMPInstance")
var ErrUnsupportedOperation = errors.New("ErrUnsupportedOperation")
var ErrNoPermission = errors.New("ErrNoPermission")
var ErrUnsupportedPacketData = errors.New("ErrUnsupportedPacketData")

// ErrNoData is returned by FuncPDUControlDynamicSubtree when no data is returned.
var ErrNoData = errors.New("no data")
