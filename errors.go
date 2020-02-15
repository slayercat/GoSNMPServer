package GoSNMPServer

import "github.com/pkg/errors"

var ErrUnsupportedProtoVersion = errors.New("ErrUnsupportedProtoVersion")
var ErrNoSNMPInstance = errors.New("ErrNoSNMPInstance")
var ErrUnsupportedOperation = errors.New("ErrUnsupportedOperation")
var ErrNoPermission = errors.New("ErrNoPermission")
var ErrUnsupportedPacketData = errors.New("ErrUnsupportedPacketData")
