package runner

import "github.com/projectdiscovery/naabu/pkg/scan"

func (r *Runner) ping(ips []string) (ip string, err error) {
	// Scan the hosts found for ping probes
	pingResults, err := scan.PingHosts(ips)
	if err != nil {
		return "", err
	}

	// Get the fastest host in the list of hosts
	fastestHost, err := pingResults.GetFastestHost()
	if err != nil {
		return "", err
	}
	return fastestHost.Host, nil
}

func (r *Runner) pingOrDefault(ips []string) (ip string) {
	if ip, err := r.ping(ips); err != nil {
		return ip
	}

	return ips[0]
}
