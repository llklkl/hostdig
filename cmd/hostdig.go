package cmd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/llklkl/hostdig/cmd/internal/localdns"
	log2 "github.com/llklkl/hostdig/cmd/internal/log"
	"github.com/llklkl/hostdig/config"
)

var rootCmd = &cobra.Command{
	Use:   "hostdig",
	Short: "a tool to dig all ip of hosts",
	Long:  ``,
	Run:   Run,
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

var (
	hc *http.Client
)

func doHttpGet(path string, data []byte, timeout time.Duration) ([]byte, int, error) {
	var req *http.Request
	var err error
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer func() {
			cancel()
		}()

		req, err = http.NewRequestWithContext(ctx, "GET", path, bytes.NewReader(data))
	} else {
		req, err = http.NewRequest("GET", path, bytes.NewReader(data))
	}
	if err != nil {
		return nil, 0, fmt.Errorf("new request failed, path=%s, err=%s", path, err.Error())
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("do request failed, path=%s, err=%s", path, err.Error())
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read response data failed, path=%s, statue_code=%d, err=%s", path, resp.StatusCode, err.Error())
	}

	return respData, resp.StatusCode, nil
}

func fetchDnsServersFromRemote(address string) ([]string, error) {
	data, _, err := doHttpGet(address, nil, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("download dns server list failed, err=%s", err.Error())
	}

	reader := bufio.NewReader(bytes.NewReader(data))
	dnsServers := make([]string, 0)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil {
			if err == io.EOF {
				dnsServers = append(dnsServers, line)
				break
			}
			continue
		}
		dnsServers = append(dnsServers, line)
	}

	return dnsServers, nil
}

func fetchDnsServersFromFile(filename string) ([]string, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("download dns server list failed, err=%s", err.Error())
	}

	reader := bufio.NewReader(fp)
	dnsServers := make([]string, 0)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err == io.EOF {
			dnsServers = append(dnsServers, line)
			break
		}

		dnsServers = append(dnsServers, line)
	}

	return dnsServers, nil
}

func getDnsList(list []config.DnsListEntry) []string {
	dnsServers := make([]string, 0)
	for _, e := range list {
		var err error
		var res []string
		switch e.Type {
		case "file":
			res, err = fetchDnsServersFromFile(e.Path)
		case "remote":
			res, err = fetchDnsServersFromRemote(e.Path)
		}

		if err != nil {
			log.Printf("load dns list failed, err=%s", err.Error())
			continue
		}

		dnsServers = append(dnsServers, res...)
	}

	return dnsServers
}

func doDnsResolve(host string, dnsAddress string) ([]string, error) {
	client := dns.Client{
		Timeout: 2 * time.Second,
	}

	if !strings.HasSuffix(host, ".") {
		host = host + "."
	}
	msg := &dns.Msg{}
	msg.SetQuestion(host, dns.TypeA)
	r, _, err := client.Exchange(msg, dnsAddress+":53")
	if err != nil {
		return nil, err
	}

	result := make([]string, 0)
	for _, rr := range r.Answer {
		recode, isType := rr.(*dns.A)
		if isType {
			result = append(result, recode.A.String())
		}
	}

	return result, nil
}

func concurrentDnsResolve(dnsServers []string, host string) ([]string, error) {
	if len(host) < 1 {
		return nil, fmt.Errorf("unexpected hosts")
	}

	mp := map[string]struct{}{}
	result := make([]string, 0)
	mx := sync.Mutex{}

	wg := sync.WaitGroup{}
	ch := make(chan struct{}, 16)
	for _, dnsAddress := range dnsServers {
		wg.Add(1)
		ch <- struct{}{}
		go func(dnsAddress string) {
			ips, err := doDnsResolve(host, dnsAddress)
			if err == nil {
				mx.Lock()
				for _, ip := range ips {
					if _, exist := mp[ip]; !exist {
						result = append(result, ip)
						mp[ip] = struct{}{}
					}
				}
				mx.Unlock()
			}

			wg.Done()
			<-ch
		}(dnsAddress)
	}

	wg.Wait()
	close(ch)

	return result, nil
}

func loadHosts(filename string) ([]string, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	res := make([]string, 0)
	reader := bufio.NewReader(fp)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				line = strings.TrimSpace(line)
				res = append(res, line)
				break
			}
			continue
		}

		line = strings.TrimSpace(line)
		res = append(res, line)
	}

	return res, nil
}

func doTestTcpLatency(ip string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), timeout)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()

	return time.Now().Sub(start), nil
}

func doTestHttpLatency(host, ip string, timeout time.Duration) (time.Duration, error) {
	ld := localdns.New()
	ld.Update(host, ip)

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	hc = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host := addr[:strings.LastIndex(addr, ":")]
				if ip, err := ld.Resolve(host); err == nil {
					addr = ip + addr[strings.LastIndex(addr, ":"):]
				}

				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s", host), nil)
	if err != nil {
		return 0, err
	}
	_, err = hc.Do(req)
	if err != nil {
		return 0, err
	}

	return time.Now().Sub(start), nil
}

// concurrentTestLatency test ips' latency, and return the fast one
func concurrentTestLatency(host string, ips []string) (string, error) {
	type testResult struct {
		Ip      string
		Latency time.Duration
	}

	wg := sync.WaitGroup{}
	ch := make(chan testResult, 1)
	con := make(chan struct{}, 16)
	for _, ip := range ips {
		wg.Add(1)
		con <- struct{}{}
		go func(ip string) {
			latency, err := doTestHttpLatency(host, ip, 4*time.Second)
			if err == nil {
				ch <- testResult{
					Ip:      ip,
					Latency: latency,
				}
			}

			wg.Done()
			<-con
		}(ip)
	}

	var fastIp string
	var minLatency = time.Hour
	go func() {
		for r := range ch {
			if r.Latency < minLatency {
				minLatency = r.Latency
				fastIp = r.Ip
			}
		}
	}()

	wg.Wait()
	close(ch)
	close(con)

	if minLatency == time.Hour {
		return "", fmt.Errorf("cannot connect to those ips[%v]", ips)
	}

	return fastIp, nil
}

func hostdig(cfg *config.Config) string {
	builder := strings.Builder{}

	dnsServers := getDnsList(cfg.DnsList)

	now := time.Now().Format(time.RFC3339)
	for _, hs := range cfg.HostsCfg {
		filepath.Walk(hs.Path, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				log.Printf("read host file failed, err=%s", err.Error())
				return nil
			}

			if !info.IsDir() {
				hosts, err := loadHosts(path)
				if err != nil {
					log.Printf("unexpected error occurred while load hosts from file, err=%s", err.Error())
					return nil // continue
				}

				// write header
				if builder.Len() > 0 {
					builder.WriteString("\n")
				}
				builder.WriteString(fmt.Sprintf("# %s update at %s\n", filepath.Base(path), now))

				for _, h := range hosts {
					ips, err := concurrentDnsResolve(dnsServers, h)
					if err != nil {
						log.Printf("unexpected error occurred while resolve host[%s], err=%s", h, err.Error())
						continue
					}

					fastip, err := concurrentTestLatency(h, ips)
					if err != nil {
						log.Printf("unexpected error occurred while test latency for host[%s], err=%s", h, err.Error())
						continue
					}

					builder.WriteString(fmt.Sprintf("%s %s\n", fastip, h))
				}
			}

			return nil
		})
	}

	return builder.String()
}

func startServe(cmd *cobra.Command, listenOn string, period int64) {
	mx := sync.Mutex{}
	cache, cached := "", false

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mx.Lock()
		defer mx.Unlock()
		if !cached {
			w.WriteHeader(503)
			return
		}

		_, _ = w.Write([]byte(cache))
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			mx.Lock()
			cache = hostdig(cfg)
			cached = true
			defer mx.Unlock()
		}()

		_, _ = w.Write([]byte("ok"))
	})

	cmd.Println("listen on", listenOn)
	cmd.Println("usage:")
	cmd.Printf("    get hosts: curl -XGET http://127.0.0.1%s\n", listenOn[strings.LastIndex(listenOn, ":"):])
	cmd.Printf("    force refresh: curl -XGET http://127.0.0.1%s/refresh\n", listenOn[strings.LastIndex(listenOn, ":"):])

	exit := make(chan struct{}, 1)
	go func() {
		err := http.ListenAndServe(listenOn, nil)
		if err != nil {
			cmd.PrintErrln("unexpected error occurred, err:", err.Error())
		}
		exit <- struct{}{}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGQUIT)
	timer := time.NewTimer(time.Second)
loop:
	for {
		select {
		case <-timer.C:
			mx.Lock()
			cache = hostdig(cfg)
			cached = true
			mx.Unlock()

			timer.Reset(time.Duration(period) * time.Second)
		case <-sigs:
			break loop
		case <-exit:
			break loop
		}
	}

	close(exit)
	close(sigs)

	cmd.Println("bye!")
}

func writeResult(cmd *cobra.Command, output string) error {
	if !quiet {
		cmd.Println("start dig hosts...")
	}
	hosts := hostdig(cfg)
	if !quiet {
		cmd.Println("done")
	}

	var fp *os.File
	var err error
	if len(output) > 0 {
		fp, err = os.OpenFile(output, os.O_CREATE|os.O_WRONLY, 0755)
	} else {
		fp = os.Stdout
	}
	if err != nil {
		cmd.PrintErrln("cannot open the specified file, err:", err.Error())
		return err
	}

	if len(output) > 0 {
		if !quiet {
			cmd.Printf("hosts has written to file[%s]", output)
		}
	} else {
		if !quiet {
			cmd.Println("hosts:\n")
		}
	}

	offset := 0
	for offset < len(hosts) {
		n, err := fp.WriteString(hosts[offset:])
		if err != nil {
			cmd.PrintErrf("error occurred while write to file[%s],err: %s\n", output, err.Error())
			break
		}

		offset += n
	}

	return nil
}

func loadConfig(filename string) error {
	fp, err := os.Open(filename)
	if err != nil {
		return err
	}

	cfg = &config.Config{}
	if err := yaml.NewDecoder(fp).Decode(cfg); err != nil {
		return err
	}

	return nil
}

var (
	cfg *config.Config
)

var (
	cfgPath string // path to config file
	output  string // output file, default stdout
	listen  string // deploy a server and listen on this addr
	period  int64  // refresh period
	quiet   bool
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime)
	hc = &http.Client{}

	cobra.OnInitialize(func() {
		if err := loadConfig(cfgPath); err != nil {
			rootCmd.PrintErrln("failed to read config file, err:", err.Error())
			os.Exit(-1)
		}
	})

	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "./config.yaml", "config file (default is ./config.yaml)")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "output file (default is stdout)")
	rootCmd.Flags().StringVarP(&listen, "listen", "l", "", "start a server and listen on this address, example: --listen=:8080")
	rootCmd.Flags().Int64VarP(&period, "period", "", 24*3600, "set the refresh period in seconds, only if the listen option was set")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "no print hint msg")
}

func Run(cmd *cobra.Command, args []string) {
	if quiet {
		log.SetOutput(log2.NopWriter{})
	}

	if len(listen) != 0 {
		startServe(cmd, listen, period)
	}

	cobra.CheckErr(writeResult(cmd, output))
}
