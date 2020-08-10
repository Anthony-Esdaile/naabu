package runner

import (
	"net"
	"syscall"
	"time"

	"github.com/projectdiscovery/naabu/pkg/scan"
)

func (r *Runner) probe(ips []string) (resultIps []string) {
	for _, ip := range ips {
		if r.pingprobes(ip) || r.synprobes(ip) || r.ackprobes(ip) {
			resultIps = append(resultIps, ip)
		}
	}

	return
}

func (r *Runner) pingprobes(ip string) bool {
	result := true

	if r.options.IcmpEchoProbe {
		result = result && scan.PingIcmpEchoRequest(ip, time.Duration(r.options.Timeout)*time.Millisecond)
	}
	if r.options.IcmpTimestampProbe {
		result = result || scan.PingIcmpTimestampRequest(ip, time.Duration(r.options.Timeout)*time.Millisecond)
	}

	return result
}

func (r *Runner) synprobes(ip string) bool {
	for p := range r.synprobesports {
		ok, err := scan.ConnectPort(ip, p, time.Duration(r.options.Timeout)*time.Millisecond)
		if ok || hasRefusedConnection(err) {
			return true
		}
	}

	return false
}

func (r *Runner) ackprobes(ip string) bool {
	for p := range r.synprobesports {
		ok, err := r.scanner.ACKPort(ip, p, time.Duration(r.options.Timeout)*time.Millisecond)
		if ok && err == nil {
			return true
		}
	}
	return false
}

func hasRefusedConnection(err error) bool {
	// no error
	if err == nil {
		return false
	}

	// timeout
	if netError, ok := err.(net.Error); ok && netError.Timeout() {
		return false
	}

	switch t := err.(type) {
	case *net.OpError:
		// Unknown host
		if t.Op == "dial" {
			return false
		}

		// Connection refused
		if t.Op == "read" {
			return true
		}

	case syscall.Errno:
		// Connection refused
		if t == syscall.ECONNREFUSED {
			return true
		}
	}

	return false
}
