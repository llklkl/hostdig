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

func readDnsServersFromData(reader *bufio.Reader) []string {
	dnsServers := make([]string, 0)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if len(line) > 0 {
			dnsServers = append(dnsServers, line)
		}
		if err != nil {
			break
		}
	}

	return dnsServers
}

func fetchDnsServersFromRemote(address string) ([]string, error) {
	data, _, err := doHttpGet(address, nil, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("download dns server list failed, err=%s", err.Error())
	}

	reader := bufio.NewReader(bytes.NewReader(data))
	return readDnsServersFromData(reader), nil
}

func fetchDnsServersFromFile(filename string) ([]string, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("download dns server list failed, err=%s", err.Error())
	}

	reader := bufio.NewReader(fp)
	return readDnsServersFromData(reader), nil
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

			<-ch
			wg.Done()
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
		line = strings.TrimSpace(line)
		if len(line) > 0 {
			res = append(res, line)
		}
		if err != nil {
			break
		}
	}

	return res, nil
}

func doTestTcpLatency(host, ip string, timeout time.Duration) (time.Duration, error) {
	if !quiet {
		fmt.Printf("test %s %s\n", host, ip)
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), timeout)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()

	return time.Now().Sub(start), nil
}

func doTestHttpLatency(host, ip string, timeout time.Duration) (time.Duration, error) {
	if !quiet {
		fmt.Printf("test %s %s\n", host, ip)
	}
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

	var fastIp string
	var minLatency = time.Hour
	var mx sync.Mutex

	wg := sync.WaitGroup{}
	con := make(chan struct{}, 16)
	for _, ip := range ips {
		wg.Add(1)
		con <- struct{}{}
		go func(ip string) {
			var latency time.Duration
			var err error
			if testType == "http" {
				latency, err = doTestHttpLatency(host, ip, 4*time.Second)
			} else {
				latency, err = doTestTcpLatency(host, ip, 4*time.Second)
			}
			if err == nil {
				mx.Lock()
				if latency < minLatency {
					minLatency = latency
					fastIp = ip
				}
				mx.Unlock()
			}

			<-con
			wg.Done()
		}(ip)
	}

	wg.Wait()
	close(con)

	if minLatency == time.Hour && !quiet {
		return "", fmt.Errorf("cannot connect to those ips[%v]", ips)
	}

	return fastIp, nil
}

func fmtAsString(builder *strings.Builder) func(string, string) {
	return func(host string, ip string) {
		builder.WriteString(ip)
		builder.WriteString(" ")
		builder.WriteString(host)
		builder.WriteString("\n")
	}
}

func hostdig(cfg *config.Config, formater func(string, string)) {
	dnsServers := getDnsList(cfg.DnsList)

	for _, hs := range cfg.HostsCfg {
		filepath.Walk(hs.Path, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				log.Printf("read host file failed, err=%s", err.Error())
				return nil
			}
			if info.IsDir() {
				return nil
			}

			hosts, err := loadHosts(path)
			if err != nil {
				log.Printf("unexpected error occurred while load hosts from file, err=%s", err.Error())
				return nil // continue
			}

			for _, h := range hosts {
				ips, err := concurrentDnsResolve(dnsServers, h)
				if err != nil {
					log.Printf("unexpected error occurred while resolve host[%s], err=%s", h, err.Error())
					continue
				}

				if !quiet {
					fmt.Printf("dig host %s, ip=%v\n", h, ips)
					fmt.Println("testing latency")
				}

				fastip, err := concurrentTestLatency(h, ips)
				if err != nil {
					if !quiet {
						fmt.Println("all timeout")
					}
					continue
				}

				if len(fastip) > 0 {
					if !quiet {
						fmt.Printf("the fastest ip is %s\n", fastip)
					}
					formater(h, fastip)
				}
			}

			return nil
		})
	}
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
			builder := strings.Builder{}
			hostdig(cfg, fmtAsString(&builder))
			mx.Lock()
			cache = builder.String()
			cached = true
			mx.Unlock()
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
			builder := strings.Builder{}
			hostdig(cfg, fmtAsString(&builder))
			mx.Lock()
			cache = builder.String()
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

	if !quiet {
		cmd.Println("bye!")
	}
}

func writeFile(fp *os.File, buf string) error {
	offset := 0
	for offset < len(buf) {
		n, err := fp.WriteString(buf[offset:])
		if err != nil {
			return fmt.Errorf("error occurred while write to file[%s],err: %s\n", output, err.Error())
		}

		offset += n
	}

	return fp.Sync()
}

func writeResult(cmd *cobra.Command, output string) error {
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
	defer fp.Close()

	if !quiet {
		cmd.Println("start dig hosts...")
	}
	builder := strings.Builder{}
	hostdig(cfg, fmtAsString(&builder))
	hosts := builder.String()
	if !quiet {
		cmd.Println("done")
	}

	if len(output) == 0 && !quiet {
		cmd.Println("hosts:")
	}

	if err := writeFile(fp, hosts); err != nil {
		cmd.PrintErrln(err)
	}
	if len(output) > 0 && !quiet {
		cmd.Printf("hosts has written to file[%s]", output)
	}

	return nil
}

func replaceResult(cmd *cobra.Command, output string) error {
	hostMap := make(map[string]string)
	hostdig(cfg, func(host string, ip string) {
		hostMap[host] = ip
	})

	fp, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		cmd.PrintErrln("cannot open the specified file, err:", err.Error())
		return err
	}
	defer fp.Close()

	needAppend := make(map[string]string, len(hostMap))
	for k, v := range hostMap {
		needAppend[k] = v
	}
	builder := strings.Builder{}
	reader := bufio.NewReader(fp)
	stop := false
	whiteLine := 0
	for !stop {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				stop = true
			} else {
				break
			}
		}

		pos := strings.IndexByte(line, '#')
		if pos == -1 {
			pos = len(line)
		}

		strs := strings.Split(strings.TrimSpace(line[:pos]), " ")
		if len(strs) <= 1 {
			if len(strings.TrimSpace(line)) == 0 { //white line
				whiteLine++
			} else {
				whiteLine = 0
			}
			if whiteLine < 2 {
				builder.WriteString(line)
			}
			continue
		}
		whiteLine = 0

		exist := map[string]struct{}{}
		flag := false // anyone exists, remain this line
		for i := 1; i < len(strs); i++ {
			if len(strs[i]) == 0 {
				continue
			}
			if ip, e := hostMap[strs[i]]; e && ip != strs[0] {
				exist[strs[i]] = struct{}{}
			} else {
				flag = true
				delete(needAppend, strs[i])
			}
		}

		if len(exist) == 0 {
			builder.WriteString(line)
		} else if flag {
			builder.WriteString(strs[0])
			builder.WriteString(" ")
			for i := 1; i < len(strs); i++ {
				if len(strs[i]) == 0 { // space
					continue
				}
				if _, e := exist[strs[i]]; !e {
					builder.WriteString(strs[i])
					builder.WriteString(" ")
				}
			}

			builder.WriteString(line[pos:])
			if pos != len(line) {
				builder.WriteString("\n")
			}
		}
	}

	builder.WriteString("\n")
	for host, ip := range needAppend {
		builder.WriteString(ip)
		builder.WriteString(" ")
		builder.WriteString(host)
		builder.WriteString("\n")
	}

	if _, err := fp.Seek(0, 0); err != nil {
		cmd.PrintErrf("error occurred while write to file[%s],err: %s\n", output, err.Error())
		return err
	} else {
		if err := fp.Truncate(0); err != nil {
			cmd.PrintErrf("error occurred while write to file[%s],err: %s\n", output, err.Error())
			return err
		}
	}

	return writeFile(fp, builder.String())
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
	testType string // type of testing latency, default is http
	cfgPath  string // path to config file
	output   string // output file, default stdout
	replace  bool   // replace output file
	listen   string // deploy a server and listen on this addr
	period   int64  // refresh period
	quiet    bool
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime)
	hc = &http.Client{}

	cobra.OnInitialize(func() {
		if rootCmd.Flags().NFlag() == 0 {
			rootCmd.Usage()
			os.Exit(0)
		}
		if err := loadConfig(cfgPath); err != nil {
			rootCmd.PrintErrln("failed to read config file, err:", err.Error())
			os.Exit(1)
		}
	})

	rootCmd.Flags().SortFlags = false
	rootCmd.Flags().StringVarP(&cfgPath, "config", "c", "", "config file path")
	rootCmd.Flags().StringVarP(&testType, "type", "t", "tcp", "the type of testing latency, support tcp or http, default is tcp")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "output file (default is stdout)")
	rootCmd.Flags().BoolVarP(&replace, "replace", "r", false, "replace the ip in the specified output file")
	rootCmd.Flags().StringVarP(&listen, "listen", "l", "", "start a server and listen on this address, example: --listen=:8080")
	rootCmd.Flags().Int64VarP(&period, "period", "", 24*3600, "set the refresh period in seconds, only if the listen option was set")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "not print log info")
}

func Run(cmd *cobra.Command, args []string) {
	if quiet {
		log.SetOutput(log2.NopWriter{})
	}

	if len(listen) != 0 {
		startServe(cmd, listen, period)
	} else if !replace || len(output) == 0 {
		cobra.CheckErr(writeResult(cmd, output))
	} else {
		cobra.CheckErr(replaceResult(cmd, output))
	}
}
