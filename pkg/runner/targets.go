package runner

import (
	"bufio"
	"errors"
	"os"

	"github.com/projectdiscovery/naabu/pkg/scan"
)

func (r *Runner) loadTargets() error {
	// Check if only a single host is sent as input. Process the host now.
	if r.options.Host != "" {
		r.targets[r.options.Host] = struct{}{}
	}

	// If we have multiple hosts as input,
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			r.add(scanner.Text())
		}
		f.Close()
	}

	// If we have STDIN input, treat it as multiple hosts
	if r.options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			r.add(scanner.Text())
		}
	}

	if len(r.targets) == 0 {
		return errors.New("No targets specified")
	}

	return nil
}

func (r *Runner) add(target string) error {
	if target == "" {
		return nil
	}
	if scan.IsCidr(target) {
		ips, err := scan.Ips(target)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			r.internalAdd(ip)
		}
		return nil
	}
	r.internalAdd(target)
	return nil
}

func (r *Runner) internalAdd(target string) error {
	ips, err := r.host2ips(target)
	if err != nil {
		return err
	}

	// As default take the first available IP
	ip := ips[0]

	// perform probes if necessary
	if !r.options.NoProbe {
		ips = r.probe(ips)
	}

	// perform ping if requested
	if r.options.Ping {
		ip = r.pingOrDefault(ips)
	}

	_, toExclude := r.excludedIps[ip]
	if toExclude {
		return nil
	}

	r.targets[ip] = struct{}{}
	return nil
}
