package runner

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/pkg/scan"
	"github.com/remeh/sizedwaitgroup"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options *Options
	scanner *scan.Scanner

	ports          map[int]struct{}
	excludedIps    map[string]struct{}
	wg             sync.WaitGroup
	targets        map[string]struct{}
	synprobesports map[int]struct{}
	ackprobesports map[int]struct{}
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	var err error
	runner.ports, err = ParsePorts(options)
	if err != nil {
		return nil, err
	}

	err = runner.parseProbesPorts(options)
	if err != nil {
		return nil, err
	}

	runner.excludedIps, err = parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	runner.targets = make(map[string]struct{})

	return runner, nil
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	err := r.loadTargets()
	if err != nil {
		return err
	}

	// Connect Scan - Preload targets and perform ports spray scan
	if !isRoot() {
		return r.ConnectEnumeration()
	}

	// Syn Scan - Perform full scan towards the same host
	return r.RawSocketEnumeration()
}

func (r *Runner) RawSocketEnumeration() error {
	kvr := NewKVResults()
	swg := sizedwaitgroup.New(r.options.Rate)

	for target := range r.targets {
		swg.Add()
		go r.handleHost(&swg, target, kvr)
	}

	swg.Wait()

	r.handleOutput(kvr)

	return nil
}

func (r *Runner) ConnectEnumeration() error {
	// naive algorithm - ports spray
	kvr := NewKVResults()
	swg := sizedwaitgroup.New(r.options.Rate)

	for retry := 0; retry < r.options.Retries; retry++ {
		for port := range r.ports {
			for target := range r.targets {
				swg.Add()
				go r.handleHostPort(&swg, target, port, kvr)
			}
		}
	}

	swg.Wait()

	r.handleOutput(kvr)

	return nil
}

func (r *Runner) handleHostPort(swg *sizedwaitgroup.SizedWaitGroup, host string, port int, kvr *KVResults) {
	defer swg.Done()

	if kvr.Has(host, port) {
		return
	}

	open, err := scan.ConnectPort(host, port, time.Duration(r.options.Timeout)*time.Millisecond)
	if open && err == nil {
		kvr.AddPort(host, port)
	}
}

func (r *Runner) handleHost(swg *sizedwaitgroup.SizedWaitGroup, host string, kvr *KVResults) {
	defer swg.Done()

	scanner, err := scan.NewScanner(time.Duration(r.options.Timeout)*time.Millisecond, r.options.Retries, r.options.Rate, r.options.Debug)
	if err != nil {
		gologger.Warningf("Could not start scan on host %s: %s\n", host, host, err)
		return
	}

	results, _ := scanner.ScanSyn(host, r.ports)
	kvr.SetPorts(host, results)
}

func (r *Runner) handleOutput(kvr *KVResults) {
	var (
		file   *os.File
		err    error
		output string
	)
	if r.options.Output != "" {
		output = r.options.Output
		// If the output format is json, append .json
		// else append .txt
		if r.options.OutputDirectory != "" {
			if r.options.JSON {
				output += ".json"
			} else {
				output += ".txt"
			}
		}
		file, err = os.Create(output)
		if err != nil {
			gologger.Errorf("Could not create file %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}

	for host, ports := range kvr.m {
		gologger.Infof("Found %d ports on host %s\n", len(ports), host)

		// console output
		if r.options.JSON {
			data := JSONResult{Host: host}
			for port := range ports {
				data.Port = port
				b, err := json.Marshal(data)
				if err != nil {
					continue
				}
				gologger.Silentf("%s\n", string(b))
			}
		} else {
			for _, port := range ports {
				gologger.Silentf("%s:%d\n", host, port)
			}
		}

		// file output
		if file != nil {
			if r.options.JSON {
				err = WriteJSONOutput(host, ports, file)
			} else {
				err = WriteHostOutput(host, ports, file)
			}
			if err != nil {
				gologger.Errorf("Could not write results to file %s for %s: %s\n", output, host, err)
			}
		}
	}
}
