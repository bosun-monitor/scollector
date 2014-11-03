package collect

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/StackExchange/scollector/opentsdb"
	"github.com/StackExchange/slog"
)

func queuer() {
	type sentValue struct {
		time time.Time
		val  interface{}
	}
	sent := make(map[string]*sentValue)
	for dp := range tchan {
		qlock.Lock()
		since := time.Now().Add(-IgnoreDuplicate)
		for {
			if len(queue) > MaxQueueLen {
				slock.Lock()
				dropped++
				slock.Unlock()
				break
			}
			key := dp.Metric + dp.Tags.String()
			if prev, ok := sent[key]; ok && prev.val == dp.Value && prev.time.After(since) {
				slock.Lock()
				duplicate++
				slock.Unlock()
			} else {
				sent[key] = &sentValue{
					time: time.Now(),
					val:  dp.Value,
				}
				queue = append(queue, dp)
			}
			select {
			case dp = <-tchan:
				continue
			default:
			}
			break
		}
		qlock.Unlock()
	}
}

func send() {
	for {
		qlock.Lock()
		if i := len(queue); i > 0 {
			if i > BatchSize {
				i = BatchSize
			}
			sending := queue[:i]
			queue = queue[i:]
			if Debug {
				slog.Infof("sending: %d, remaining: %d", i, len(queue))
			}
			qlock.Unlock()
			sendBatch(sending)
		} else {
			qlock.Unlock()
			time.Sleep(time.Second)
		}
	}
}

func sendBatch(batch opentsdb.MultiDataPoint) {
	var buf bytes.Buffer
	g := gzip.NewWriter(&buf)
	if err := json.NewEncoder(g).Encode(batch); err != nil {
		slog.Error(err)
		return
	}
	if err := g.Close(); err != nil {
		slog.Error(err)
		return
	}
	req, err := http.NewRequest("POST", tsdbURL, &buf)
	if err != nil {
		slog.Error(err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	// Some problem with connecting to the server; retry later.
	if err != nil || resp.StatusCode != http.StatusNoContent {
		if err != nil {
			slog.Error(err)
		} else if resp.StatusCode != http.StatusNoContent {
			slog.Errorln(resp.Status)
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				slog.Error(err)
			}
			if len(body) > 0 {
				slog.Error(string(body))
			}
		}
		t := time.Now().Add(-time.Minute * 30).Unix()
		old := 0
		restored := 0
		for _, dp := range batch {
			if dp.Timestamp < t {
				old++
				continue
			}
			restored++
			tchan <- dp
		}
		if old > 0 {
			slog.Infof("removed %d old records", old)
		}
		d := time.Second * 5
		slog.Infof("restored %d, sleeping %s", restored, d)
		time.Sleep(d)
		return
	} else {
		if Debug {
			slog.Infoln("sent", len(batch))
		}
		slock.Lock()
		sent += int64(len(batch))
		slock.Unlock()
	}
}
