package dirsearch

import (
	"bytes"
	"context"
	"slack-wails/lib/clients"
	"slack-wails/lib/gologger"
	"slack-wails/lib/util"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/panjf2000/ants/v2"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	bodyLengthMap map[int]int
	mutex         = sync.Mutex{}
)

type Result struct {
	Status    int
	URL       string
	Location  string
	Length    int
	Body      string
	Recursion int
}

type Options struct {
	Method                 string
	URLs                   []string
	Paths                  []string
	Workers                int
	Timeout                int
	BodyExclude            string
	BodyLengthExcludeTimes int // 过滤响应包长度数据次数出现了多少次，就过滤相同的
	StatusCodeExclude      []int
	Redirect               bool
	Interval               int
	CustomHeader           string
	Recursion              int
}

// method 请求类型
func NewScanner(ctx, ctrlCtx context.Context, o Options) {
	runtime.EventsEmit(ctx, "dirsearchCounts", len(o.URLs)*len(o.Paths))
	bodyLengthMap = make(map[int]int)
	// 初始化请求信息
	if o.Timeout == 0 {
		o.Timeout = 8
	}
	client := clients.NewRestyClient(nil, o.Redirect)
	headers := clients.Str2HeadersMap(o.CustomHeader)
	var id int32
	single := make(chan struct{})
	retChan := make(chan Result)
	var wg sync.WaitGroup
	go func() {
		for pr := range retChan {
			pr.Recursion = o.Recursion
			runtime.EventsEmit(ctx, "dirsearchLoading", pr)
		}
		close(single)
		runtime.EventsEmit(ctx, "dirsearchComplete", "done")
	}()

	dirScan := func(url string) {
		r := Scan(ctx, url, headers, o, client)
		atomic.AddInt32(&id, 1)
		runtime.EventsEmit(ctx, "dirsearchProgressID", id)
		retChan <- r
	}
	threadPool, _ := ants.NewPoolWithFunc(o.Workers, func(p interface{}) {
		path := p.(string)
		dirScan(path)
		wg.Done()
	})
	defer threadPool.Release()
	for _, url := range o.URLs {
		url = prettyURL(url)
		for _, path := range o.Paths {
			if ctrlCtx.Err() != nil {
				return
			}
			path = prettyPath(path)
			wg.Add(1)
			threadPool.Invoke(url + path)
			if o.Interval != 0 {
				time.Sleep(time.Second * time.Duration(o.Interval))
			}
		}
	}
	wg.Wait()
	close(retChan)
	<-single
}

// status 1 表示被排除显示在外，不计入前端ERROR请求中
func Scan(ctx context.Context, url string, header map[string]string, o Options, client *resty.Client) Result {
	var result Result
	result.URL = url
	resp, err := clients.DoRequest(o.Method, url, header, nil, o.Timeout, client)
	if err != nil {
		gologger.IntervalError(ctx, err)
		return result
	}
	if o.BodyExclude != "" && bytes.Contains(resp.Body(), []byte(o.BodyExclude)) {
		result.Status = 1
		return result
	} else {
		result.Status = resp.StatusCode()
	}
	if util.ArrayContains(result.Status, o.StatusCodeExclude) {
		result.Status = 1
		return result
	}
	result.Length = len(resp.Body())
	// 记录同一状态码下长度出现次数，当次数超过o.BodyLengthExcludeTimes时，将状态码设置为1，过滤显示
	mutex.Lock()
	bodyLengthMap[result.Length]++
	if bodyLengthMap[result.Length] > o.BodyLengthExcludeTimes {
		result.Status = 1
	}
	mutex.Unlock()
	result.Body = string(resp.Body())
	result.Location = resp.Header().Get("Location")
	return result
}

func prettyURL(url string) string {
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}
	return url
}

func prettyPath(path string) string {
	if strings.HasPrefix(path, "/") {
		path = strings.TrimLeft(path, "/")
	}
	return path
}
