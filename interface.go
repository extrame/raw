package raw

import "net"

type Interface interface {
	Name() string
	Index() int
	MTU() int
	Flags() net.Flags
	Addrs() ([]net.Addr, error)
	HardwareAddr() []byte
}
