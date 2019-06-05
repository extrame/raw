package raw

import (
	"errors"
	"net"

	"github.com/google/gopacket/pcap"
)

type interfaceWindwows struct {
	dev *pcap.Interface
}

func (i *interfaceWindwows) Name() string {
	return i.dev.Name
}

func (i *interfaceWindwows) Index() int {
	return 0
}

func (i *interfaceWindwows) Flags() net.Flags {
	return net.Flags(i.dev.Flags)
}

func (i *interfaceWindwows) MTU() int {
	return 1600
}

type addrWindows struct {
	addr *pcap.InterfaceAddress
}

func (a *addrWindows) Network() string {
	return a.addr.Netmask.String()
}

func (a *addrWindows) String() string {
	return a.addr.IP.String()
}

func (a *interfaceWindwows) HardwareAddr() net.HardwareAddr {
	return []byte{1, 2, 3, 4, 5, 6}
}

func (i *interfaceWindwows) Addrs() ([]net.Addr, error) {
	var addresses = make([]net.Addr, len(i.dev.Addresses))
	for index := 0; index < len(i.dev.Addresses); index++ {
		addresses[index] = &addrWindows{
			addr: &i.dev.Addresses[index],
		}
	}
	return addresses, nil
}

func Interfaces() ([]Interface, error) {
	if devs, err := pcap.FindAllDevs(); err == nil {
		var is = make([]Interface, len(devs))
		for index := 0; index < len(devs); index++ {
			var iface interfaceWindwows
			iface.dev = &devs[index]
			is[index] = &iface
		}
		return is, nil
	} else {
		return nil, err
	}
}

func InterfaceByName(name string) (Interface, error) {
	if devs, err := pcap.FindAllDevs(); err == nil {
		for index := 0; index < len(devs); index++ {
			if devs[index].Name == name {
				return &interfaceWindwows{
					dev: &devs[index],
				}, nil
			}
		}
		return nil, errors.New("No such device")
	} else {
		return nil, err
	}
}
