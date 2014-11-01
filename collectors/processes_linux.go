// +build linux

package collectors

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/StackExchange/scollector/opentsdb"
)

func init() {
	collectors = append(collectors, &IntervalCollector{F: c_linux_processes})
}

//Will move this to collectors since this is something that should be reusable
//IDPool is not concurrent safe
type IDPool struct {
	Free []int
	Next int
}

func NewIDPool() *IDPool {
	p := IDPool{Next: 0}
	return &p
}

func (i *IDPool) Get() int {
	if len(i.Free) == 0 {
		i.Next++
		return i.Next
	}
	sort.Ints(i.Free)
	return i.Free[0]
}

func (i *IDPool) Put(v int) {
	i.Free = append(i.Free, v)
}

type WatchedProcess struct {
	Command   string
	Name      string
	Processes map[string]LinuxProcess
	Argmatch  regexp.Regexp
	*IDPool
}

func NewWatchedProcess(command, name, argmatch string) *WatchedProcess {
	r := regexp.MustCompile(argmatch)
	return &WatchedProcess{
		Command:   command,
		Name:      name,
		Processes: make(map[string]LinuxProcess),
		Argmatch:  *r,
		IDPool:    NewIDPool(),
	}
}

type LinuxProcess struct {
	Pid       string
	Command   string
	Arguments []string
}

func GetLinuxProccesses() ([]LinuxProcess, error) {
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []string
	for _, f := range files {
		if _, err := strconv.Atoi(f.Name()); err == nil && f.IsDir() {
			pids = append(pids, f.Name())
		}
	}
	var lps []LinuxProcess
	for _, pid := range pids {
		cmdline, err := ioutil.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			//Continue because the pid might not exist any more
			continue
		}
		cl := strings.Split(string(cmdline), "\x00")
		if len(cl) < 1 || len(cl[0]) == 0 {
			continue
		}
		lp := LinuxProcess{
			Pid:     pid,
			Command: cl[0],
		}
		if len(cl) > 1 {
			for _, arg := range cl[1:] {
				lp.Arguments = append(lp.Arguments, arg)
			}
		}
		lps = append(lps, lp)
	}
	return lps, nil
}

func c_linux_processes() (opentsdb.MultiDataPoint, error) {
	var md opentsdb.MultiDataPoint
	pids, err := GetLinuxProccesses()
	if err != nil {
		return nil, nil
	}
	fmt.Println(pids)
	return md, nil
}
