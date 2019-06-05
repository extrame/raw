package raw

import (
	"net"

	"github.com/pkg/errors"
)

type Interface interface {
	Name() string
	Index() int
	MTU() int
	Flags() net.Flags
	Addrs() ([]net.Addr, error)
	HardwareAddr() net.HardwareAddr
}

func NewInterfaceDelegate(index int, name string) Interface {
	return &interfaceDelegate{
		_Index: index,
		_Name:  name,
	}
}

type interfaceDelegate struct {
	_Index int
	_Name  string
}

func (l *interfaceDelegate) Addrs() ([]net.Addr, error) {
	return nil, errors.New("should not used")
}

func (l *interfaceDelegate) Flags() net.Flags {
	return 0
}

func (l *interfaceDelegate) HardwareAddr() net.HardwareAddr {
	return nil
}

func (l *interfaceDelegate) Index() int {
	return l._Index
}

func (l *interfaceDelegate) MTU() int {
	return 0
}

func (l *interfaceDelegate) Name() string {
	return l._Name
}
