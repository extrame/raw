package raw

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

var lowerInterfaces []pcap.Interface

type packetConn struct {
	ifi     Interface
	pcapIfi *pcap.Interface
	handle  *pcap.Handle
	pbe     uint16
	source  *gopacket.PacketSource
}

// ReadFrom implements the net.PacketConn.ReadFrom method.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	var err error
	var packet gopacket.Packet
	packet, err = p.source.NextPacket()
	for err == nil {
		var link = packet.LinkLayer()
		if el, ok := link.(*layers.Ethernet); ok {
			if !bytes.Equal(el.SrcMAC, p.ifi.HardwareAddr()) {
				n := copy(b, packet.Data())
				return n, &Addr{
					HardwareAddr: el.SrcMAC,
				}, err
			} else {
				goto fetchNext
			}
		} else {
			return 0, nil, errors.New("NOT ETHER PACKET")
		}
	fetchNext:
		packet, err = p.source.NextPacket()
	}
	return 0, nil, err
}

// htons converts a short (uint16) from host-to-network byte order.
// Thanks to mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// listenPacket creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func listenPacket(ifi Interface, proto uint16, cfg Config) (*packetConn, error) {
	var wifi *interfaceWindwows
	var ok bool
	if wifi, ok = ifi.(*interfaceWindwows); !ok {
		return nil, errors.New("not corrent ifi type")
	}

	fmt.Println(fmt.Sprintf("ether proto 0x%x", proto))
	if handle, err := pcap.OpenLive(ifi.Name(), 1600, true, pcap.BlockForever); err != nil {
		return nil, errors.Wrap(err, "in open live")
	} else if err := handle.SetBPFFilter(fmt.Sprintf("ether proto 0x%x", proto)); err != nil { // optional
		return nil, errors.Wrap(err, "in set bpf")
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		return &packetConn{
			source:  packetSource,
			handle:  handle,
			ifi:     ifi,
			pcapIfi: wifi.dev,
		}, nil
	}
}

func (p *packetConn) Close() error {
	p.handle.Close()
	return nil
}

// WriteTo implements the net.PacketConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := p.handle.WritePacketData(b); err == nil {
		return len(b), nil
	} else {
		return 0, err
	}
}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {
	return &Addr{
		HardwareAddr: p.ifi.HardwareAddr(),
	}
}

// SetDeadline is not currently implemented on this platform.
func (p *packetConn) SetDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetReadDeadline is not currently implemented on this platform.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetWriteDeadline is not currently implemented on this platform.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetBPF is not currently implemented on this platform.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	return ErrNotImplemented
}

// SetPromisc is not currently implemented on this platform.
func (p *packetConn) SetPromiscuous(b bool) error {
	return ErrNotImplemented
}

// Stats is not currently implemented on this platform.
func (p *packetConn) Stats() (*Stats, error) {
	return nil, ErrNotImplemented
}
