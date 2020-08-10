package scan

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Some constants
const (
	ProtocolICMP = 1
)

// PingResult contains the results for the Ping request
type PingResult struct {
	Hosts []Ping
}

// Ping contains the results for ping on a single host
type Ping struct {
	Type    PingResultType
	Latency time.Duration
	Error   error
	Host    string
}

// PingResultType contains the type of result for ping request on an address
type PingResultType int

// Type of ping responses
const (
	HostInactive PingResultType = iota
	HostActive
)

// PingHosts pings the addresses given and returns the latencies of each host
// If the address returns an error, that address is marked as unusable.
func PingHosts(addresses []string) (*PingResult, error) {
	// Start listening for icmp replies
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	results := &PingResult{Hosts: []Ping{}}
	var sequence int

	for _, addr := range addresses {
		// Resolve any DNS (if used) and get the real IP of the target
		dst, err := net.ResolveIPAddr("ip4", addr)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		sequence++
		// Make a new ICMP message
		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  sequence,
				Data: []byte(""),
			},
		}

		data, err := m.Marshal(nil)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		// Send the packet
		start := time.Now()
		n, err := c.WriteTo(data, dst)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		reply := make([]byte, 1500)
		err = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		n, _, err = c.ReadFrom(reply)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		duration := time.Since(start)

		rm, err := icmp.ParseMessage(ProtocolICMP, reply[:n])
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			results.Hosts = append(results.Hosts, Ping{Type: HostActive, Latency: duration, Host: addr})
		default:
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: errors.New("no reply found for ping probe"), Host: addr})
		}
	}

	return results, nil
}

// GetFastestHost gets the fastest host from the ping responses
func (p *PingResult) GetFastestHost() (Ping, error) {
	var ping Ping

	// If the latency of the current host is less than the
	// host selected and host is active, use the host that has least latency.
	for _, host := range p.Hosts {
		if (host.Latency < ping.Latency || ping.Latency == 0) && host.Type == HostActive {
			ping.Type = HostActive
			ping.Latency = host.Latency
			ping.Host = host.Host
		}
	}

	if ping.Type != HostActive {
		return ping, errors.New("no active host found for target")
	}
	return ping, nil
}

func PingIcmpEchoRequest(ip string, timeout time.Duration) bool {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte(""),
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}

	n, err := c.WriteTo(data, destAddr)
	if err != nil {
		return false
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	n, sourceIp, err := c.ReadFrom(reply)
	// timeout
	if err != nil {
		return false
	}
	// if anything is read from the connection it means that the host is alive
	if destAddr.String() == sourceIp.String() && n > 0 {
		return true
	}

	return false
}

func PingIcmpTimestampRequest(ip string, timeout time.Duration) bool {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	m := icmp.Message{
		Type: ipv4.ICMPTypeTimestamp,
		Code: 0,
		Body: &Timestamp{
			ID:              os.Getpid() & 0xffff,
			Seq:             0,
			OriginTimestamp: 0,
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}

	n, err := c.WriteTo(data, destAddr)
	if err != nil {
		return false
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	n, sourceIp, err := c.ReadFrom(reply)
	// timeout
	if err != nil {
		return false
	}
	// if anything is read from the connection it means that the host is alive
	if destAddr.String() == sourceIp.String() && n > 0 {
		return true
	}

	return false
}

type Timestamp struct {
	ID                int
	Seq               int
	OriginTimestamp   uint32
	ReceiveTimestamp  uint32
	TransmitTimestamp uint32
}

const marshalledTimestampLen = 16

func (t *Timestamp) Len(_ int) int {
	if t == nil {
		return 0
	}
	return marshalledTimestampLen
}

func (t *Timestamp) Marshal(_ int) ([]byte, error) {
	b := make([]byte, marshalledTimestampLen)
	b[0], b[1] = byte(t.ID>>8), byte(t.ID)
	b[2], b[3] = byte(t.Seq>>8), byte(t.Seq)

	unparseInt := func(i uint32) (byte, byte, byte, byte) {
		return byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)
	}
	b[4], b[5], b[6], b[7] = unparseInt(t.OriginTimestamp)
	b[8], b[9], b[10], b[11] = unparseInt(t.ReceiveTimestamp)
	b[12], b[13], b[14], b[15] = unparseInt(t.TransmitTimestamp)
	return b, nil
}

func ParseTimestamp(_ int, b []byte) (icmp.MessageBody, error) {
	bodyLen := len(b)
	if bodyLen != marshalledTimestampLen {
		return nil, fmt.Errorf("timestamp body length %d not equal to 16", bodyLen)
	}
	p := &Timestamp{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}

	parseInt := func(start int) uint32 {
		return uint32(b[start])<<24 | uint32(b[start+1])<<16 | uint32(b[start+2])<<8 | uint32(b[start+3])
	}
	p.OriginTimestamp = parseInt(4)
	p.ReceiveTimestamp = parseInt(8)
	p.TransmitTimestamp = parseInt(12)
	return p, nil
}
