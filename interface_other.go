// +build !windows

package raw

import (
	"net"

	"github.com/pkg/errors"
)

func NewInterface(ifi *net.Interface) Interface {
	return &bsdInterface{
		ifi: ifi,
	}
}

type bsdInterface struct {
	ifi *net.Interface
}

func (l *bsdInterface) Addrs() ([]net.Addr, error) {
	return l.ifi.Addrs()
}

func (l *bsdInterface) Flags() net.Flags {
	return l.ifi.Flags
}

func (l *bsdInterface) HardwareAddr() net.HardwareAddr {
	return l.ifi.HardwareAddr
}

func (l *bsdInterface) Index() int {
	return l.ifi.Index
}

func (l *bsdInterface) MTU() int {
	return l.ifi.MTU
}

func (l *bsdInterface) Name() string {
	return l.ifi.Name
}

func InterfaceByName(name string) (Interface, error) {
	if ifis, err := net.Interfaces(); err == nil {
		for _, ifi := range ifis {
			if ifi.Name == name {
				return &bsdInterface{
					ifi: &ifi,
				}, nil
			}
		}
		return nil, errors.New("no such device")
	} else {
		return nil, err
	}
}

func InterfaceByIndex(i int) (Interface, error) {
	if ifis, err := net.Interfaces(); err == nil {
		for _, ifi := range ifis {
			if ifi.Index == i {
				return &bsdInterface{
					ifi: &ifi,
				}, nil
			}
		}
		return nil, errors.New("no such device")
	} else {
		return nil, err
	}
}

func Interfaces() ([]Interface, error) {
	if ifis, err := net.Interfaces(); err == nil {
		var rawIfis = make([]Interface, len(ifis))
		for index := 0; index < len(ifis); index++ {
			rawIfis[index] = &bsdInterface{
				ifi: &ifis[index],
			}
		}
		return rawIfis, nil
	} else {
		return nil, err
	}
}
