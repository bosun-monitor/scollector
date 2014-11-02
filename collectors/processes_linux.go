// +build linux

package collectors

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/StackExchange/scollector/metadata"
	"github.com/StackExchange/scollector/opentsdb"
)

var conf []WatchedProcess

// LinuxProcesses registers the LinuxProcesses collector.
func LinuxProcesses(raw_conf []string) error {
	for _, cs := range raw_conf {
		s := strings.SplitN(cs, ",", 4)
		if len(s) != 3 {
			return fmt.Errorf("not enough arguments for the linux process collector with %s", cs)
		}
		conf = append(conf, *NewWatchedProcess(s[0], s[1], s[2]))
	}

	collectors = append(collectors, &IntervalCollector{
		F: func() (opentsdb.MultiDataPoint, error) {
			return c_linux_processes(conf)
		},
		name: "linux_processes",
	})
	return nil
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
	Processes map[string]int
	ArgMatch  regexp.Regexp
	*IDPool
}

func (w *WatchedProcess) Check(l *LinuxProcess) {
	if _, ok := w.Processes[l.Pid]; ok {
		return
	}
	if !strings.Contains(l.Command, w.Command) {
		return
	}
	if w.ArgMatch.MatchString(l.Arguments) {
		w.Processes[l.Pid] = w.Get()
	}
}

func (w *WatchedProcess) Remove(pid string) {
	w.Put(w.Processes[pid])
	delete(w.Processes, pid)
}

func (w *WatchedProcess) Monitor(md *opentsdb.MultiDataPoint) {
	for pid, id := range w.Processes {
		stats_file, err := ioutil.ReadFile("/proc/" + pid + "/stat")
		if err != nil {
			w.Remove(pid)
			return
		}
		io_file, err := ioutil.ReadFile("/proc/" + pid + "/io")
		if err != nil {
			w.Remove(pid)
			return
		}
		stats := strings.Fields(string(stats_file))
		var io []string
		for _, line := range strings.Split(string(io_file), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				io = append(io, f[1])
			}
		}
		Add(md, "linux.proc.cpu", stats[13], opentsdb.TagSet{"type": "user", "name": w.Name, "id": strconv.Itoa(id)}, metadata.Counter, metadata.Pct, "")
	}
}

func NewWatchedProcess(command, name, argmatch string) *WatchedProcess {
	r := regexp.MustCompile(argmatch)
	return &WatchedProcess{
		Command:   command,
		Name:      name,
		Processes: make(map[string]int),
		ArgMatch:  *r,
		IDPool:    NewIDPool(),
	}
}

type LinuxProcess struct {
	Pid       string
	Command   string
	Arguments string
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
			lp.Arguments = strings.Join(cl[1:], "")
		}
		lps = append(lps, lp)
	}
	return lps, nil
}

func c_linux_processes(conf []WatchedProcess) (opentsdb.MultiDataPoint, error) {
	var md opentsdb.MultiDataPoint
	lps, err := GetLinuxProccesses()
	if err != nil {
		return nil, nil
	}
	for _, w := range conf {
		for _, lp := range lps {
			w.Check(&lp)
		}
	}
	for _, w := range conf {
		w.Monitor(&md)
	}
	return md, nil
}
