package collectors

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/StackExchange/scollector/metadata"
	"github.com/StackExchange/scollector/opentsdb"
)

// HTTP registers an http_check collector for a given url + options.
func HTTP(h []string) {
	collectors = append(collectors, &IntervalCollector{
		F: func() (opentsdb.MultiDataPoint, error) {
			return c_http_check(h)
		},
		name: fmt.Sprintf("http-%s", h[0]),
	})
}

func c_http_check(h []string) (opentsdb.MultiDataPoint, error) {
	var md opentsdb.MultiDataPoint
	u, err := url.Parse(h[0])
	if err != nil {
		log.Println(err)
		return md, err
	}
	headers := make(http.Header)
	if len(h) > 3 {
		for _, v := range h[3:] {
			f := strings.Split(v, ":")
			if len(f) != 2 {
				log.Println(fmt.Errorf("error parsing http header pair %v", v))
				return md, err
			}
			for _, hv := range strings.Split(f[1], ";") {
				headers.Add(strings.TrimSpace(f[0]), strings.TrimSpace(hv))
			}
		}
	}
	sh := strings.Split(u.Host, ":")
	host := sh[0]
	var port string
	if len(sh) > 1 {
		port = sh[1]
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		log.Println(err)
	}
	cli := &http.Client{}
	cli.Timeout = time.Second * 30
	for _, ip := range ips {
		var req http.Request
		nu := u
		nh := []string{ip}
		if port != "" {
			nh = append(nh, port)
		}
		nu.Host = strings.Join(nh, ":")
		req.URL = nu
		if headers.Get("User-Agent") == "" {
			headers.Set("User-Agent", "bosun (StackExchange)")
		}
		req.Header = headers
		req.Host = host
		if hh := headers.Get("Host"); hh != "" {
			//Setting host header doesn't work
			req.Host = hh
		}
		st := time.Now()
		resp, err := cli.Do(&req)
		if err != nil {
			return md, nil
		}
		d := time.Now().Sub(st)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
		}
		//TODO This won't work with IPv6 due to colons
		ts := opentsdb.TagSet{"dst_host": req.Host, "ip": ip}
		if len(h) > 1 {
			fmt.Println(h[1])
			ts["route"] = h[1]
		}
		Add(&md, "http.check.response_time", d.Seconds()*1000, ts, metadata.Gauge, metadata.MilliSecond, "")
		Add(&md, "http.check.response_code", resp.StatusCode, ts, metadata.Gauge, metadata.ResponseCode, "")
		if len(h) > 2 {
			var b int
			if strings.Contains(string(body), h[2]) {
				b = 1
			}
			Add(&md, "http.check.string_found", b, ts, metadata.Gauge, metadata.Bool, "")
		}
	}
	return md, nil
}
