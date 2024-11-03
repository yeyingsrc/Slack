package webscan

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	rt "runtime"
	"slack-wails/core/subdomain"
	"slack-wails/core/waf"
	"slack-wails/lib/clients"
	"slack-wails/lib/gologger"
	"slack-wails/lib/netutil"
	"slack-wails/lib/structs"
	"slack-wails/lib/util"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/panjf2000/ants/v2"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	iconRels = []string{"icon", "shortcut icon", "apple-touch-icon", "mask-icon"}
	ExitFunc = false
)

type WebInfo struct {
	Protocol      string
	Port          int
	Path          string
	Title         string
	StatusCode    int
	IconHash      string // mmh3
	IconMd5       string // md5
	BodyString    string
	HeadeString   string
	ContentType   string
	Server        string
	ContentLength int
	// Banner        string // tcp指纹
	Cert string // TLS证书
}

type InfoResult struct {
	URL          string
	StatusCode   int
	Length       int
	Title        string
	Fingerprints []string
	IsWAF        bool
	WAF          string
	Detect       string
	Screenshot   string // 截图图片路径
}

type FingerScanner struct {
	ctx                     context.Context
	urls                    []*url.URL
	aliveURLs               []*url.URL          // 默认指纹扫描结束后，存活的URL，以便后续主动指纹过滤目标
	screenshot              bool                // 是否截屏
	thread                  int                 // 指纹线程
	deepScan                bool                // 代表主动指纹探测
	rootPath                bool                // 主动指纹是否采取根路径扫描
	basicURLWithFingerprint map[string][]string // 后续nuclei需要扫描的目标列表
	generateLog4j2          bool                // 是否添加Log4j2指纹，后续nuclei可以添加扫描
	client                  *http.Client
	notFollowClient         *http.Client
	mutex                   sync.RWMutex
}

func NewFingerScanner(ctx context.Context, proxy clients.Proxy, options structs.WebscanOptions) *FingerScanner {
	urls := make([]*url.URL, 0, len(options.Target)) // 提前分配容量
	for _, t := range options.Target {
		u, err := url.Parse(t)
		if err != nil {
			continue
		}
		urls = append(urls, u)
	}
	if len(urls) == 0 {
		gologger.Error(ctx, "未发现可用目标，请检查输入")
		return nil
	}
	return &FingerScanner{
		ctx:                     ctx,
		urls:                    urls,
		client:                  clients.DefaultWithProxyClient(proxy),
		notFollowClient:         clients.NotFollowWithProxyClient(proxy),
		screenshot:              options.Screenshot,
		thread:                  options.Thread,
		deepScan:                options.DeepScan,
		rootPath:                options.RootPath,
		basicURLWithFingerprint: make(map[string][]string),
		generateLog4j2:          options.GenerateLog4j2,
	}
}

func (s *FingerScanner) NewFingerScan() {
	var wg sync.WaitGroup
	single := make(chan struct{})
	retChan := make(chan InfoResult, len(s.urls))
	go func() {
		for pr := range retChan {
			runtime.EventsEmit(s.ctx, "webFingerScan", pr)
		}
		close(single)
	}()
	// 指纹扫描
	fscan := func(u *url.URL) {
		if ExitFunc {
			return
		}
		var (
			rawHeaders   []byte
			faviconHash  string
			faviconMd5   string
			server       string
			content_type string
			statusCode   int
		)

		// 先进行一次不会重定向的扫描，可以获得重定向前页面的响应头中获取指纹
		resp, _, _ := clients.NewSimpleGetRequest(u.String(), s.notFollowClient)
		if resp != nil && resp.StatusCode == 302 {
			rawHeaders = DumpResponseHeadersOnly(resp)
		}

		// 正常请求指纹
		resp, body, err := clients.NewSimpleGetRequest(u.String(), s.client)
		if err != nil || resp == nil {
			if len(rawHeaders) > 0 {
				gologger.Debug(s.ctx, fmt.Sprintf("%s hash error to 302, response headers: %s", u.String(), string(rawHeaders)))
				statusCode = 302
				goto ContinueExecution
			}
			// 如果是正常的无法响应则直接返回
			retChan <- InfoResult{
				URL:        u.String(),
				StatusCode: 0,
			}
			return
		}

		// 合并请求头数据
		rawHeaders = append(rawHeaders, DumpResponseHeadersOnly(resp)...)

		// 请求Logo
		faviconHash, faviconMd5 = FaviconHash(u, s.client)

		// 发送shiro探测
		rawHeaders = append(rawHeaders, []byte(fmt.Sprintf("Set-Cookie: %s", s.ShiroScan(u)))...)

	ContinueExecution:
		// 跟随JS重定向，并替换成重定向后的数据
		redirectBody := s.GetJSRedirectResponse(u, string(body))
		if redirectBody != nil {
			body = redirectBody
		}
		// 网站正常响应
		title := clients.GetTitle(body)
		if resp != nil {
			server = resp.Header.Get("Server")
			content_type = resp.Header.Get("Content-Type")
			statusCode = resp.StatusCode
		}
		web := &WebInfo{
			HeadeString:   string(rawHeaders),
			ContentType:   content_type,
			Cert:          GetTLSString(u.Scheme, u.Host),
			BodyString:    string(body),
			Path:          u.Path,
			Title:         title,
			Server:        server,
			ContentLength: len(body),
			Port:          netutil.GetPort(u),
			IconHash:      faviconHash,
			IconMd5:       faviconMd5,
			StatusCode:    statusCode,
		}

		wafInfo := *waf.ResolveAndWafIdentify(u.Hostname(), subdomain.DefaultDnsServers)

		s.aliveURLs = append(s.aliveURLs, u)

		fingerprints := s.FingerScan(s.ctx, web, FingerprintDB)

		if s.generateLog4j2 {
			fingerprints = append(fingerprints, "Generate-Log4j2")
		}

		if s.FastjsonScan(u) {
			fingerprints = append(fingerprints, "Fastjson")
		}

		if len(fingerprints) >= 20 {
			fingerprints = []string{"疑似蜜罐"}
		}

		// 截屏
		var screenshotPath string
		if s.screenshot {
			if screenshotPath, err = GetScreenshot(u.String()); err != nil {
				gologger.Debug(s.ctx, err)
			}
		}

		s.mutex.Lock()
		s.basicURLWithFingerprint[u.String()] = append(s.basicURLWithFingerprint[u.String()], fingerprints...)
		s.mutex.Unlock()

		retChan <- InfoResult{
			URL:          u.String(),
			StatusCode:   web.StatusCode,
			Length:       web.ContentLength,
			Title:        web.Title,
			Fingerprints: fingerprints,
			IsWAF:        wafInfo.Exsits,
			WAF:          wafInfo.Name,
			Detect:       "Default",
			Screenshot:   screenshotPath,
		}
	}
	threadPool, _ := ants.NewPoolWithFunc(50, func(target interface{}) {
		t := target.(*url.URL)
		fscan(t)
		wg.Done()
	})
	defer threadPool.Release()
	for _, target := range s.urls {
		if ExitFunc {
			return
		}
		wg.Add(1)
		threadPool.Invoke(target)
	}
	wg.Wait()
	close(retChan)
	gologger.Info(s.ctx, "FingerScan Finished")
	<-single
}

type TFP struct {
	URL  *url.URL
	Fpe  []FingerPEntity
	Path string
}

func (s *FingerScanner) NewActiveFingerScan(rootPath bool) {
	if len(s.aliveURLs) == 0 {
		gologger.Warning(s.ctx, "未发现存活目标，已跳过主动指纹扫描")
		return
	}
	gologger.Info(s.ctx, "正在进行主动指纹探测 ...")
	var id = 0
	var wg sync.WaitGroup
	visited := make(map[string]bool) // 用于记录已访问的URL和路径组合

	single := make(chan struct{})
	retChan := make(chan InfoResult, len(s.urls))
	go func() {
		for pr := range retChan {
			runtime.EventsEmit(s.ctx, "webFingerScan", pr)
		}
		close(single)
	}()
	// 主动指纹扫描
	threadPool, _ := ants.NewPoolWithFunc(5, func(tfp interface{}) {
		defer wg.Done()
		fp := tfp.(TFP)
		fullURL := fp.URL.String() + fp.Path

		// 确保并发唯一性：检查和标记已经访问过的URL和路径组合
		s.mutex.Lock()
		if visited[fullURL] {
			s.mutex.Unlock()
			return // 已经处理过，跳过
		}
		visited[fullURL] = true
		s.mutex.Unlock()

		resp, body, _ := clients.NewRequest("GET", fullURL, nil, nil, 5, false, s.client)
		if resp == nil {
			return
		}

		server := resp.Header.Get("Server")
		content_type := resp.Header.Get("Content-Type")
		title := clients.GetTitle(body)

		headers, _, _ := DumpResponseHeadersAndRaw(resp)
		ti := &WebInfo{
			HeadeString:   string(headers),
			ContentType:   content_type,
			BodyString:    string(body),
			Path:          fp.Path,
			Title:         title,
			Server:        server,
			ContentLength: len(body),
			Port:          netutil.GetPort(fp.URL),
			StatusCode:    resp.StatusCode,
		}
		result := s.FingerScan(s.ctx, ti, fp.Fpe)
		if len(result) > 0 {
			s.mutex.Lock()
			s.basicURLWithFingerprint[fp.URL.String()] = append(s.basicURLWithFingerprint[fp.URL.String()], result...)
			s.mutex.Unlock()

			retChan <- InfoResult{
				URL:          fullURL,
				StatusCode:   ti.StatusCode,
				Length:       ti.ContentLength,
				Title:        ti.Title,
				Fingerprints: []string{fp.Fpe[0].ProductName},
				Detect:       "Active",
			}
		}
	})
	defer threadPool.Release()
	s.ActiveCounts()
	// 载入存活目标
	for _, target := range s.aliveURLs {
		for _, afdb := range ActiveFingerprintDB {
			for _, path := range afdb.Path {
				if ExitFunc { // 控制程序退出
					return
				}
				wg.Add(1)
				id += 1
				runtime.EventsEmit(s.ctx, "ActiveProgressID", id)
				if rootPath {
					target, _ = url.Parse(util.GetBasicURL(target.String()))
				}
				threadPool.Invoke(TFP{
					URL:  target,
					Fpe:  afdb.Fpe,
					Path: path,
				})
			}
		}
	}
	wg.Wait()
	close(retChan)
	gologger.Info(s.ctx, "ActiveFingerScan Finished")
	runtime.EventsEmit(s.ctx, "ActiveScanComplete", 100)
	<-single
}

// 统计主动指纹总共要扫描的目标
func (s *FingerScanner) ActiveCounts() {
	var id = 0
	for _, afdb := range ActiveFingerprintDB {
		id += len(afdb.Path)
	}
	count := len(s.aliveURLs) * id
	runtime.EventsEmit(s.ctx, "ActiveCounts", count)
}

func (s *FingerScanner) URLWithFingerprintMap() map[string][]string {
	return s.basicURLWithFingerprint
}

// DumpResponseHeadersOnly 只返回响应头
func DumpResponseHeadersOnly(resp *http.Response) []byte {
	headers, _ := httputil.DumpResponse(resp, false)
	return headers
}

// DumpResponseHeadersAndRaw returns http headers and response as strings
func DumpResponseHeadersAndRaw(resp *http.Response) (headers, fullresp []byte, err error) {
	// httputil.DumpResponse does not work with websockets
	if resp.StatusCode >= http.StatusContinue && resp.StatusCode <= http.StatusEarlyHints {
		raw := resp.Status + "\n"
		for h, v := range resp.Header {
			raw += fmt.Sprintf("%s: %s\n", h, v)
		}
		return []byte(raw), []byte(raw), nil
	}
	headers, err = httputil.DumpResponse(resp, false)
	if err != nil {
		return
	}
	// logic same as httputil.DumpResponse(resp, true) but handles
	// the edge case when we get both error and data on reading resp.Body
	var buf1, buf2 bytes.Buffer
	b := resp.Body
	if _, err = buf1.ReadFrom(b); err != nil {
		if buf1.Len() <= 0 {
			return
		}
	}
	if err == nil {
		_ = b.Close()
	}

	// rewind the body to allow full dump
	resp.Body = io.NopCloser(bytes.NewReader(buf1.Bytes()))
	err = resp.Write(&buf2)
	fullresp = buf2.Bytes()

	// rewind once more to allow further reuses
	resp.Body = io.NopCloser(bytes.NewReader(buf1.Bytes()))
	return
}

func (s *FingerScanner) FingerScan(ctx context.Context, web *WebInfo, targetDB []FingerPEntity) []string {
	var fingerPrintResults []string

	workers := rt.NumCPU() * 2
	inputChan := make(chan FingerPEntity, len(targetDB))
	defer close(inputChan)
	results := make(chan string, len(targetDB))
	defer close(results)

	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			if found != "" {
				fingerPrintResults = append(fingerPrintResults, found)
			}
			wg.Done()
		}
	}()
	//多指纹同时扫描
	for i := 0; i < workers; i++ {
		go func() {
			for finger := range inputChan {
				expr := finger.AllString
				for _, rule := range finger.Rule {
					var result bool
					switch rule.Key {
					case "header":
						result = dataCheckString(rule.Op, web.HeadeString, rule.Value)
					case "body":
						result = dataCheckString(rule.Op, web.BodyString, rule.Value)
					case "server":
						result = dataCheckString(rule.Op, web.Server, rule.Value)
					case "title":
						result = dataCheckString(rule.Op, web.Title, rule.Value)
					case "cert":
						result = dataCheckString(rule.Op, web.Cert, rule.Value)
					case "port":
						value, err := strconv.Atoi(rule.Value)
						if err == nil {
							result = dataCheckInt(rule.Op, web.Port, value)
						}
					case "protocol":
						result = (rule.Op == 0 && web.Protocol == rule.Value) || (rule.Op == 1 && web.Protocol != rule.Value)
					case "path":
						result = dataCheckString(rule.Op, web.Path, rule.Value)
					case "icon_hash":
						value, err := strconv.Atoi(rule.Value)
						hashIcon, errHash := strconv.Atoi(web.IconHash)
						if err == nil && errHash == nil {
							result = dataCheckInt(rule.Op, hashIcon, value)
						}
					case "icon_mdhash":
						result = dataCheckString(rule.Op, web.IconMd5, rule.Value)
					case "status":
						value, err := strconv.Atoi(rule.Value)
						if err == nil {
							result = dataCheckInt(rule.Op, web.StatusCode, value)
						}
					case "content_type":
						result = dataCheckString(rule.Op, web.ContentType, rule.Value)
						// case "banner":
						// 	result = dataCheckString(rule.Op, web.Banner, rule.Value)
					}

					if result {
						expr = expr[:rule.Start] + "T" + expr[rule.End:]
					} else {
						expr = expr[:rule.Start] + "F" + expr[rule.End:]
					}
				}
				r := boolEval(ctx, expr)
				if r {
					results <- finger.ProductName
				} else {
					results <- ""
				}
			}
		}()
	}
	//添加扫描目标
	for _, input := range targetDB {
		wg.Add(1)
		inputChan <- input
	}
	wg.Wait()
	return util.RemoveDuplicates(fingerPrintResults)
}

// parseIcons 解析HTML文档head中的<link>标签中rel属性包含icon信息的href链接
func parseIcons(doc *goquery.Document) []string {
	var icons []string
	doc.Find("head link").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			// 匹配ICON链接
			if rel, exists := s.Attr("rel"); exists && util.ArrayContains(rel, iconRels) {
				icons = append(icons, href)
			}
		}
	})
	// 找不到自定义icon链接就使用默认的favicon地址
	if len(icons) == 0 {
		icons = append(icons, "favicon.ico")
	}
	return icons
}

// 获取favicon Mmh3Hash32 和 MD5值
func FaviconHash(u *url.URL, client *http.Client) (string, string) {
	_, body, err := clients.NewSimpleGetRequest(u.String(), client)
	if err != nil {
		return "", ""
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return "", ""
	}
	iconLink := parseIcons(doc)[0]
	var finalLink string
	// 如果是完整的链接，则直接请求
	if strings.HasPrefix(iconLink, "http") {
		finalLink = iconLink
		// 如果为 // 开头采用与网站同协议
	} else if strings.HasPrefix(iconLink, "//") {
		finalLink = u.Scheme + ":" + iconLink
	} else {
		finalLink = fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, iconLink)
	}
	resp, body, err := clients.NewSimpleGetRequest(finalLink, client)
	if err == nil && resp.StatusCode == 200 {
		hasher := md5.New()
		hasher.Write(body)
		sum := hasher.Sum(nil)
		return util.Mmh3Hash32(util.Base64Encode(body)), hex.EncodeToString(sum)
	}
	return "", ""
}

// func (s *FingerScanner) GetBanner(u *url.URL) string {
// 	if strings.HasPrefix(u.Scheme, "http") {
// 		return ""
// 	}
// 	scanner := gonmap.New()
// 	_, response := scanner.Scan(u.Host, netutil.GetPort(u), time.Second*time.Duration(10))
// 	if response != nil {
// 		return response.Raw
// 	}
// 	return ""
// }

func (s *FingerScanner) GetJSRedirectResponse(u *url.URL, respRaw string) []byte {
	var nextCheckUrl string
	newPath := checkJSRedirect(respRaw)
	if newPath == "" {
		return nil
	}
	newPath = strings.Trim(newPath, " ")
	newPath = strings.Trim(newPath, "'")
	newPath = strings.Trim(newPath, "\"")
	if strings.HasPrefix(newPath, "https://") || strings.HasPrefix(newPath, "http://") {
		if strings.Contains(newPath, u.Host) {
			nextCheckUrl = newPath
		}
	} else {
		if len(newPath) > 0 {
			if newPath[0] == '/' {
				newPath = newPath[1:]
			}
		}
		nextCheckUrl = getRealPath(u.Scheme+"://"+u.Host) + "/" + newPath

	}
	_, body, err := clients.NewSimpleGetRequest(nextCheckUrl, s.client)
	if err != nil {
		return nil
	}
	return body
}

// 探测shiro并返回响应头中的Set-Cookie值
func (s *FingerScanner) ShiroScan(u *url.URL) string {
	shiroHeader := map[string]string{
		"Cookie": fmt.Sprintf("JSESSIONID=%s;rememberMe=123", util.RandomStr(16)),
	}
	resp, _, err := clients.NewRequest("GET", u.String(), shiroHeader, nil, 10, false, s.client)
	if err != nil || resp == nil {
		return ""
	}
	return resp.Header.Get("Set-Cookie")
}

// 探测Fastjson
func (s *FingerScanner) FastjsonScan(u *url.URL) bool {
	jsonHeader := map[string]string{
		"Content-Type": "application/json",
	}
	_, body, err := clients.NewRequest("POST", u.String(), jsonHeader, strings.NewReader(`{"@type":"java.lang.AutoCloseable"`), 10, false, s.client)
	if err != nil || body == nil {
		return false
	}
	return bytes.Contains(body, []byte("fastjson-version"))
}
