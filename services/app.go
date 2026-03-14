package services

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slack-wails/core/dirsearch"
	"slack-wails/core/dumpall"
	"slack-wails/core/info/icp"
	"slack-wails/core/info/tianyancha"
	"slack-wails/core/isic"
	"slack-wails/core/jsfind"
	"slack-wails/core/portscan"
	"slack-wails/core/repeater"
	"slack-wails/core/space"
	"slack-wails/core/subdomain"
	"slack-wails/core/webscan"
	"slack-wails/lib/control"
	"slack-wails/lib/gologger"
	"slack-wails/lib/gomessage"
	"slack-wails/lib/structs"
	"slack-wails/lib/utils"
	"slack-wails/lib/utils/fileutil"
	"slack-wails/lib/utils/httputil"
	"slack-wails/lib/utils/netutil"
	"slack-wails/lib/utils/randutil"
	"strconv"
	"strings"
	"sync"
	"time"

	arrayutil "github.com/qiwentaidi/utils/array"

	"github.com/qiwentaidi/clients"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/xuri/excelize/v2"
	runtime "slack-wails/internal/wruntime"
)

// App struct
type App struct {
	ctx              context.Context
	webfingerFile    string
	activefingerFile string
	cdnFile          string
	qqwryFile        string
	templateDir      string
	statsCancel      context.CancelFunc
}

// NewApp creates a new App application struct
func NewApp() *App {
	home := utils.HomeDir()
	return &App{
		webfingerFile:    home + "/slack/config/webfinger.yaml",
		activefingerFile: home + "/slack/config/dir.yaml",
		cdnFile:          home + "/slack/config/cdn.yaml",
		qqwryFile:        home + "/slack/config/qqwry.dat",
		templateDir:      home + "/slack/config/pocs",
	}
}

// ServiceStartup is called when the app starts.
func (a *App) ServiceStartup(ctx context.Context, _ application.ServiceOptions) error {
	a.ctx = ctx
	a.startSystemStatsEmitter()
	return nil
}

// 返回 true 将导致应用程序继续，false 将继续正常关闭
func (a *App) BeforeClose(ctx context.Context) (prevent bool) {
	if !webscan.IsRunning {
		if a.statsCancel != nil {
			a.statsCancel()
		}
		return false
	}
	dialog, err := runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
		Type:          runtime.QuestionDialog,
		Title:         "Quit?",
		Message:       "Webscan is running are you sure you want to quit?",
		DefaultButton: "Confirm",
		CancelButton:  "Cancel",
		Buttons:       []string{"Confirm", "Cancel"},
	})
	if err != nil {
		return false
	}
	return dialog == "Cancel"
}

func (a *App) Callgologger(level, msg string) {
	switch level {
	case "info":
		gologger.Info(a.ctx, msg)
	case "warning":
		gologger.Warning(a.ctx, msg)
	case "error":
		gologger.Error(a.ctx, msg)
	case "success":
		gologger.Success(a.ctx, msg)
	default:
		gologger.Debug(a.ctx, msg)
	}
}

func (a *App) emitSystemStats() {
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercent) == 0 {
		cpuPercent = []float64{0}
	}

	memStat, err := mem.VirtualMemory()
	memPercent := float64(0)
	if err == nil && memStat != nil {
		memPercent = memStat.UsedPercent
	}

	runtime.EventsEmit(a.ctx, "system-stats", map[string]any{
		"cpu": cpuPercent[0],
		"mem": memPercent,
	})
}

func (a *App) startSystemStatsEmitter() {
	if a.statsCancel != nil {
		a.statsCancel()
	}

	a.emitSystemStats()

	ctx, cancel := context.WithCancel(a.ctx)
	a.statsCancel = cancel

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.emitSystemStats()
			}
		}
	}()
}

func (a *App) GoFetch(method, target string, body interface{}, headers map[string]string, timeout int, proxyURL string) *structs.Response {
	if _, err := url.Parse(target); err != nil {
		return &structs.Response{
			Error: true,
		}
	}
	var content []byte
	// 判断body的类型
	if data, ok := body.(map[string]interface{}); ok {
		content, _ = json.Marshal(data)
	} else {
		content = []byte(body.(string))
	}
	resp, err := clients.DoRequest(method, target, headers, bytes.NewReader(content), 10, clients.NewRestyClientWithProxy(nil, true, proxyURL))
	if err != nil {
		return &structs.Response{
			Error: true,
		}
	}
	headerMap := make(map[string]string)
	for key, values := range resp.Header() {
		// 对于每个键，创建一个新的 map 并添加键值对
		headerMap["key"] = key
		headerMap["value"] = strings.Join(values, " ")
	}
	return &structs.Response{
		Error:     false,
		Proto:     resp.Proto(),
		StatsCode: resp.StatusCode(),
		Header:    headerMap,
		Body:      string(resp.Body()),
	}
}

var qqwryLoader sync.Once

func (a *App) IpLocation(ip string) string {
	qqwryLoader.Do(func() {
		subdomain.InitQqwry(a.ctx, a.qqwryFile)
	})
	result, err := subdomain.Database.Find(ip)
	if err != nil {
		return ""
	}
	return result.String()
}

var cdndataLoader sync.Once

func (a *App) Subdomain(o structs.SubdomainOption) {
	ctrlCtx, _ := control.GetScanContext(control.Subdomain) // 标识任务
	qqwryLoader.Do(func() {
		subdomain.InitQqwry(a.ctx, a.qqwryFile)
	})
	cdndataLoader.Do(func() {
		subdomain.Cdndata = netutil.ReadCDNFile(a.ctx, a.cdnFile)
	})
	engine := subdomain.NewSubdomainEngine(a.ctx, o)
	switch o.Mode {
	case structs.EnumerationMode:
		for _, domain := range o.Domains {
			engine.Runner(ctrlCtx, domain, []string{}, "Enumeration")
		}
	case structs.ApiMode:
		engine.ApiPolymerization(ctrlCtx)
	case structs.MixedMode:
		engine.ApiPolymerization(ctrlCtx)
		for _, domain := range o.Domains {
			engine.Runner(ctrlCtx, domain, []string{}, "Enumeration")
		}
	default:
		engine.Runner(ctrlCtx, "", []string{}, "")
	}
}

func (a *App) ExitScanner(scanType string) {
	switch scanType {
	case "[subdomain]":
		control.CancelScanContext(control.Subdomain)
	case "[dirsearch]":
		control.CancelScanContext(control.Dirseach)
	case "[portscan]":
		control.CancelScanContext(control.Portscan)
		control.CancelScanContext(control.Crack)
	case "[webscan]":
		control.CancelScanContext(control.Webscan)
	}
}

func (a *App) FetchCompanyInfo(companyName string, ratio int, ds *structs.DataSource, maxDepth int) structs.CompanyInfo {
	var result structs.CompanyInfo
	if ds.Tianyancha.Enable {
		tyc := tianyancha.NewClient(a.ctx, ds.Tianyancha.Token, ds.Tianyancha.Token)
		if tyc.CheckLogin() {
			info, err := a.fetchCompanyRecursiveByTianyancha(tyc, companyName, ratio, 1, maxDepth)
			if err != nil {
				gologger.Error(a.ctx, fmt.Sprintf("[tianyancha] fetch company info error: %s", err.Error()))
			}
			a.WriteCompanyInfoToJson(info)
			result = info
		} else {
			gomessage.Warning(a.ctx, "tianyancha token is invalid")
			gologger.Warning(a.ctx, "tianyancha token is invalid")
			return structs.CompanyInfo{}
		}
	} else {
		result.CompanyName = companyName
	}

	if ds.Miit.API != "" {
		ds.Miit.API = strings.TrimRight(ds.Miit.API, "/")
		// 给主公司填充ICP信息
		a.EnrichCompanyWithMiit(&result, ds.Miit.API)
		time.Sleep(randutil.SleepRandTime(2))
		// 给所有子公司递归填充
		var enrichSubsidiaries func(subs []structs.CompanyInfo)
		enrichSubsidiaries = func(subs []structs.CompanyInfo) {
			for i := range subs {
				a.EnrichCompanyWithMiit(&subs[i], ds.Miit.API)
				if len(subs[i].Subsidiaries) > 0 {
					enrichSubsidiaries(subs[i].Subsidiaries)
				}
			}
		}
		enrichSubsidiaries(result.Subsidiaries)
	}
	a.WriteCompanyInfoToJson(result)
	return result
}

func (a *App) EnrichCompanyWithMiit(company *structs.CompanyInfo, miitApi string) {
	// 吊销或注销则跳过
	if company.RegStatus == "吊销" || company.RegStatus == "注销" {
		return
	}
	gologger.Info(a.ctx, fmt.Sprintf("[icp] 正在查询%s域名信息", company.CompanyName))
	if webResp, err := icp.FetchWebInfo(a.ctx, miitApi, company.CompanyName); err == nil {
		var domains []string
		for _, data := range webResp.Params.List {
			domains = append(domains, data.Domain)
		}
		company.Domains = domains
	} else {
		gologger.Warning(a.ctx, fmt.Sprintf("%s fetch web info error: %s", company.CompanyName, err))
	}

	time.Sleep(2 * time.Second)
	gologger.Info(a.ctx, fmt.Sprintf("[icp] 正在查询%sApp信息", company.CompanyName))
	if appResp, err := icp.FetchAppInfo(a.ctx, miitApi, company.CompanyName); err == nil {
		company.Apps = appResp.Params.List
	} else {
		gologger.Warning(a.ctx, fmt.Sprintf("%s fetch app info error: %s", company.CompanyName, err))
	}

	time.Sleep(2 * time.Second)
	gologger.Info(a.ctx, fmt.Sprintf("[icp] 正在查询%s小程序信息", company.CompanyName))
	if appletResp, err := icp.FetchAppletInfo(a.ctx, miitApi, company.CompanyName); err == nil {
		company.Applets = appletResp.Params.List
	} else {
		gologger.Warning(a.ctx, fmt.Sprintf("%s fetch applet info error: %s", company.CompanyName, err))
	}
}

func (a *App) ResumeAfterHumanCheck() {
	go func() {
		tianyancha.HumanCheckChan <- struct{}{}
	}()
}

// func (a *App) fetchCompanyRecursiveByRiskbird(rb *riskbird.RiskbirdClient, company string, ratio int, currentDepth, maxDepth int) (structs.CompanyInfo, error) {
// 	var companyInfo structs.CompanyInfo

// 	info, orderNo, err := rb.FetchBasicCompanyInfo(company)
// 	if err != nil {
// 		return companyInfo, err
// 	}
// 	companyInfo = info

// 	// Step 2: 查询 App、小程序、公众号等
// 	if apps, err := rb.FetchApp(orderNo); err == nil {
// 		companyInfo.Apps = apps
// 	}
// 	time.Sleep(1 * time.Second)

// 	if applets, err := rb.FetchApplet(orderNo); err == nil {
// 		// applets 需要转换为 OfficialAccounts，如果你有对应函数可以调用，否则跳过
// 		for _, ap := range applets {
// 			companyInfo.OfficialAccounts = append(companyInfo.OfficialAccounts, structs.OfficialAccount{
// 				Name: ap.Name, Logo: ap.Logo, Qrcode: fmt.Sprintf("%v", ap.Qrcode),
// 			})
// 		}
// 	}
// 	time.Sleep(1 * time.Second)

// 	// Step 3: 查询子公司
// 	subs, err := rb.FetchSubsidiary(orderNo)
// 	if err == nil && currentDepth <= maxDepth {
// 		for _, sub := range subs {
// 			gq, _ := strconv.Atoi(strings.TrimSuffix(sub.FunderRatio, "%"))
// 			if gq < ratio {
// 				continue
// 			}
// 			child, err := a.fetchCompanyRecursiveByRiskbird(rb, sub.EntName, ratio, currentDepth+1, maxDepth)
// 			if err != nil {
// 				gologger.Error(a.ctx, fmt.Sprintf("[riskbird] %s fetch sub error: %s", sub.EntName, err.Error()))
// 				continue
// 			}
// 			child.Investment = sub.FunderRatio
// 			child.Amount = sub.RegCapFormat
// 			child.RegStatus = sub.EntStatus
// 			companyInfo.Subsidiaries = append(companyInfo.Subsidiaries, child)
// 		}
// 	}

//		return companyInfo, nil
//	}
func (a *App) fetchCompanyRecursiveByTianyancha(tyc *tianyancha.TycClient, company string, ratio int, currentDepth, maxDepth int) (structs.CompanyInfo, error) {
	var companyInfo structs.CompanyInfo

	// Step 1: 获取公司基本信息
	suggest, err := tyc.CheckKeyMap(company)
	if err != nil {
		return companyInfo, err
	}
	companyInfo.CompanyName = suggest.ComName
	companyInfo.Investment = "母公司"
	companyInfo.RegStatus = tyc.GetRegStatus(suggest.RegStatus)
	companyInfo.Trademark = suggest.Logo

	// Step 2: 非注销/吊销状态的公司需要获取公众号信息
	if officialAccounts, err := tyc.FetchWeChatOfficialAccounts(suggest.ComName, suggest.GraphID); err == nil {
		companyInfo.OfficialAccounts = officialAccounts
	}
	time.Sleep(randutil.SleepRandTime(2))

	// Step 3: 获取子公司信息
	subsidiaries, err := tyc.FetchSubsidiary(suggest.ComName, suggest.GraphID, ratio)
	if err != nil {
		return companyInfo, err
	}

	for _, subs := range subsidiaries {
		child := structs.CompanyInfo{
			CompanyName: subs.Name,
			Investment:  subs.Percent,
			Amount:      subs.Amount,
			RegStatus:   subs.RegStatus,
			Trademark:   fmt.Sprint(subs.Logo),
		}
		// 跳过已注销或吊销的子公司
		if suggest.RegStatus != 1 && suggest.RegStatus != 2 && currentDepth < maxDepth {
			for {
				time.Sleep(2 * time.Second)
				subInfo, err := a.fetchCompanyRecursiveByTianyancha(tyc, subs.Name, ratio, currentDepth+1, maxDepth)
				if err != nil && strings.Contains(err.Error(), "账号存在风险请人机验证") {
					// 通知前端进行人机验证
					runtime.EventsEmit(a.ctx, "tyc-human-check", "天眼查出现人机校验，请手动处理")
					gologger.DualLog(a.ctx, gologger.Level_DEBUG, "天眼查出现人机校验，请手动处理")
					<-tianyancha.HumanCheckChan
					gologger.DualLog(a.ctx, gologger.Level_DEBUG, "收到用户确认，继续查询")
					continue // 重试
				}
				if err == nil {
					child.OfficialAccounts = subInfo.OfficialAccounts
					child.Subsidiaries = subInfo.Subsidiaries
				}
				break
			}
		}

		// 当前深度已达最大，或者递归处理完都要追加子公司
		companyInfo.Subsidiaries = append(companyInfo.Subsidiaries, child)
	}

	return companyInfo, nil
}

var companyPath = filepath.Join(utils.HomeDir(), "slack", "company_info")

func (a *App) WriteCompanyInfoToJson(info structs.CompanyInfo) bool {
	os.Mkdir(companyPath, 0777)
	fp := filepath.Join(companyPath, fmt.Sprintf("%s-%s.json", info.CompanyName, info.RegStatus))
	return fileutil.SaveJsonWithFormat(a.ctx, fp, info)
}

func (a *App) ExportCompanyInfoToJson(infos []structs.CompanyInfo, reportpath string) bool {
	if len(infos) == 0 || reportpath == "" {
		return false
	}
	return fileutil.SaveJsonWithFormat(a.ctx, reportpath, infos)
}

type companySummaryRow struct {
	ParentCompany string
	CompanyName   string
	Investment    string
	Amount        string
	RegStatus     string
	Depth         int
	Domains       string
}

type companyDomainRow struct {
	BelongCompany string
	Domain        string
}

type companyOfficialAccountRow struct {
	BelongCompany string
	Name          string
	Numbers       string
	Logo          string
	Qrcode        string
	Introduction  string
}

type companyAppRow struct {
	BelongCompany string
	ServiceName   string
	ServiceLicence string
	UpdateRecordTime string
	UnitName      string
}

func (a *App) ExportCompanyInfoToExcel(infos []structs.CompanyInfo, reportpath string) bool {
	f := excelize.NewFile()
	f.DeleteSheet("Sheet1")

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#1F2937"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border: []excelize.Border{
			{Type: "left", Color: "#D1D5DB", Style: 1},
			{Type: "top", Color: "#D1D5DB", Style: 1},
			{Type: "right", Color: "#D1D5DB", Style: 1},
			{Type: "bottom", Color: "#D1D5DB", Style: 1},
		},
	})
	if err != nil {
		gologger.Error(a.ctx, "Failed to create company excel header style: "+err.Error())
		return false
	}

	bodyStyle, err := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top"},
		Border: []excelize.Border{
			{Type: "left", Color: "#E5E7EB", Style: 1},
			{Type: "top", Color: "#E5E7EB", Style: 1},
			{Type: "right", Color: "#E5E7EB", Style: 1},
			{Type: "bottom", Color: "#E5E7EB", Style: 1},
		},
	})
	if err != nil {
		gologger.Error(a.ctx, "Failed to create company excel body style: "+err.Error())
		return false
	}

	wrapStyle, err := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
		Border: []excelize.Border{
			{Type: "left", Color: "#E5E7EB", Style: 1},
			{Type: "top", Color: "#E5E7EB", Style: 1},
			{Type: "right", Color: "#E5E7EB", Style: 1},
			{Type: "bottom", Color: "#E5E7EB", Style: 1},
		},
	})
	if err != nil {
		gologger.Error(a.ctx, "Failed to create company excel wrap style: "+err.Error())
		return false
	}

	var summaryRows []companySummaryRow
	var domainRows []companyDomainRow
	var officialAccountRows []companyOfficialAccountRow
	var appRows []companyAppRow
	var appletRows []companyAppRow

	var walkCompany func(parent string, info structs.CompanyInfo, depth int)
	walkCompany = func(parent string, info structs.CompanyInfo, depth int) {
		summaryRows = append(summaryRows, companySummaryRow{
			ParentCompany: parent,
			CompanyName:   info.CompanyName,
			Investment:    info.Investment,
			Amount:        info.Amount,
			RegStatus:     info.RegStatus,
			Depth:         depth,
			Domains:       strings.Join(info.Domains, "\n"),
		})

		for _, domain := range info.Domains {
			domainRows = append(domainRows, companyDomainRow{
				BelongCompany: info.CompanyName,
				Domain:        domain,
			})
		}

		for _, item := range info.OfficialAccounts {
			officialAccountRows = append(officialAccountRows, companyOfficialAccountRow{
				BelongCompany: info.CompanyName,
				Name:          item.Name,
				Numbers:       item.Numbers,
				Logo:          item.Logo,
				Qrcode:        item.Qrcode,
				Introduction:  item.Introduction,
			})
		}

		for _, item := range info.Apps {
			appRows = append(appRows, companyAppRow{
				BelongCompany:    info.CompanyName,
				ServiceName:      item.ServiceName,
				ServiceLicence:   item.ServiceLicence,
				UpdateRecordTime: item.UpdateRecordTime,
				UnitName:         item.UnitName,
			})
		}

		for _, item := range info.Applets {
			appletRows = append(appletRows, companyAppRow{
				BelongCompany:    info.CompanyName,
				ServiceName:      item.ServiceName,
				ServiceLicence:   item.ServiceLicence,
				UpdateRecordTime: item.UpdateRecordTime,
				UnitName:         item.UnitName,
			})
		}

		for _, child := range info.Subsidiaries {
			walkCompany(info.CompanyName, child, depth+1)
		}
	}

	for _, info := range infos {
		walkCompany("", info, 0)
	}

	writeSheet := func(name string, headers []string, rows [][]interface{}, wrapColumns map[int]bool) {
		f.NewSheet(name)
		maxWidths := make([]int, len(headers))
		for index, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(index+1, 1)
			f.SetCellValue(name, cell, header)
			if len([]rune(header)) > maxWidths[index] {
				maxWidths[index] = len([]rune(header))
			}
		}
		for rowIndex, row := range rows {
			for colIndex, value := range row {
				cell, _ := excelize.CoordinatesToCellName(colIndex+1, rowIndex+2)
				f.SetCellValue(name, cell, value)
				textWidth := len([]rune(fmt.Sprint(value)))
				if textWidth > maxWidths[colIndex] {
					maxWidths[colIndex] = textWidth
				}
			}
		}

		lastColumn, _ := excelize.ColumnNumberToName(len(headers))
		lastRow := len(rows) + 1
		if lastRow < 1 {
			lastRow = 1
		}
		_ = f.SetCellStyle(name, "A1", fmt.Sprintf("%s1", lastColumn), headerStyle)
		if len(rows) > 0 {
			_ = f.SetCellStyle(name, "A2", fmt.Sprintf("%s%d", lastColumn, len(rows)+1), bodyStyle)
			for colIndex := range headers {
				if wrapColumns[colIndex] {
					column, _ := excelize.ColumnNumberToName(colIndex + 1)
					_ = f.SetCellStyle(name, fmt.Sprintf("%s2", column), fmt.Sprintf("%s%d", column, len(rows)+1), wrapStyle)
				}
			}
		}
		for index, width := range maxWidths {
			column, _ := excelize.ColumnNumberToName(index + 1)
			finalWidth := float64(width + 4)
			if finalWidth < 12 {
				finalWidth = 12
			}
			if finalWidth > 48 {
				finalWidth = 48
			}
			_ = f.SetColWidth(name, column, column, finalWidth)
		}
		_ = f.SetRowHeight(name, 1, 24)
		_ = f.SetPanes(name, &excelize.Panes{
			Freeze:      true,
			Split:       false,
			XSplit:      0,
			YSplit:      1,
			TopLeftCell: "A2",
			ActivePane:  "bottomLeft",
		})
		_ = f.AutoFilter(name, fmt.Sprintf("A1:%s%d", lastColumn, lastRow), []excelize.AutoFilterOptions{})
	}

	reportTime := time.Now().Format("2006-01-02 15:04:05")
	summarySheet := "Summary"
	f.NewSheet(summarySheet)
	summaryItems := [][]interface{}{
		{"生成时间", reportTime},
		{"导出企业数", len(infos)},
		{"公司/子公司总数", len(summaryRows)},
		{"域名总数", len(domainRows)},
		{"公众号总数", len(officialAccountRows)},
		{"APP 总数", len(appRows)},
		{"小程序总数", len(appletRows)},
	}
	for rowIndex, row := range summaryItems {
		for colIndex, value := range row {
			cell, _ := excelize.CoordinatesToCellName(colIndex+1, rowIndex+1)
			f.SetCellValue(summarySheet, cell, value)
		}
	}
	_ = f.SetCellStyle(summarySheet, "A1", "A7", headerStyle)
	_ = f.SetCellStyle(summarySheet, "B1", "B7", bodyStyle)
	_ = f.SetColWidth(summarySheet, "A", "A", 18)
	_ = f.SetColWidth(summarySheet, "B", "B", 22)
	if summaryIndex, err := f.GetSheetIndex(summarySheet); err == nil {
		f.SetActiveSheet(summaryIndex)
	}

	var summaryData [][]interface{}
	for _, row := range summaryRows {
		summaryData = append(summaryData, []interface{}{
			row.ParentCompany,
			row.CompanyName,
			row.Investment,
			row.Amount,
			row.RegStatus,
			row.Depth,
			row.Domains,
		})
	}
	writeSheet("Companies", []string{"ParentCompany", "CompanyName", "Investment", "Amount", "RegStatus", "Depth", "Domains"}, summaryData, map[int]bool{6: true})

	var domainData [][]interface{}
	for _, row := range domainRows {
		domainData = append(domainData, []interface{}{row.BelongCompany, row.Domain})
	}
	writeSheet("Domains", []string{"BelongCompany", "Domain"}, domainData, nil)

	var officialAccountData [][]interface{}
	for _, row := range officialAccountRows {
		officialAccountData = append(officialAccountData, []interface{}{
			row.BelongCompany,
			row.Name,
			row.Numbers,
			row.Logo,
			row.Qrcode,
			row.Introduction,
		})
	}
	writeSheet("OfficialAccounts", []string{"BelongCompany", "Name", "Numbers", "Logo", "Qrcode", "Introduction"}, officialAccountData, map[int]bool{3: true, 4: true, 5: true})

	var appData [][]interface{}
	for _, row := range appRows {
		appData = append(appData, []interface{}{
			row.BelongCompany,
			row.ServiceName,
			row.ServiceLicence,
			row.UpdateRecordTime,
			row.UnitName,
		})
	}
	writeSheet("Apps", []string{"BelongCompany", "ServiceName", "ServiceLicence", "UpdateRecordTime", "UnitName"}, appData, nil)

	var appletData [][]interface{}
	for _, row := range appletRows {
		appletData = append(appletData, []interface{}{
			row.BelongCompany,
			row.ServiceName,
			row.ServiceLicence,
			row.UpdateRecordTime,
			row.UnitName,
		})
	}
	writeSheet("Applets", []string{"BelongCompany", "ServiceName", "ServiceLicence", "UpdateRecordTime", "UnitName"}, appletData, nil)

	if err := f.SaveAs(reportpath); err != nil {
		gologger.Error(a.ctx, "Failed to save company excel report: "+err.Error())
		return false
	}

	return true
}

// dirsearch
func (a *App) LoadDirsearchDict(dictPath, newExts []string) []string {
	var dicts []string
	for _, dict := range dictPath {
		dicts = append(dicts, LoadDirDict(dict, "%EXT%", newExts)...)
	}
	return arrayutil.RemoveDuplicates(dicts)
}

func LoadDirDict(filepath, old string, new []string) (dict []string) {
	file, _ := os.Open(filepath)
	defer file.Close()
	s := bufio.NewScanner(file)
	for s.Scan() {
		if s.Text() != "" { // 去除空行
			if len(new) > 0 {
				if strings.Contains(s.Text(), old) { // 如何新数组不为空,将old字段替换成new数组
					for _, n := range new {
						dict = append(dict, strings.ReplaceAll(s.Text(), old, n))
					}
				} else {
					dict = append(dict, s.Text())
				}
			} else {
				if !strings.Contains(s.Text(), old) {
					dict = append(dict, s.Text())
				}
			}
		}
	}
	return dict
}

func (a *App) NewDirsearchScanner(options dirsearch.Options) {
	ctrlCtx, _ := control.GetScanContext(control.Dirseach) // 标识任务
	engine := dirsearch.NewDirsearchEngine(a.ctx, ctrlCtx, options)
	if options.Backupscan {
		engine.BackupRunner(ctrlCtx)
	} else {
		engine.Runner(ctrlCtx)
	}
}

// portscan

func (a *App) HostAlive(targets []string, Ping bool) []string {
	return portscan.CheckLive(a.ctx, targets, Ping)
}

func (a *App) SpaceGetPort(ip string) []float64 {
	return space.GetShodanAllPort(a.ctx, ip)
}

func (a *App) NewTcpScanner(taskId string, specialTargets []string, ips []string, ports []int, thread, timeout int, proxyURL string) {
	ctrlCtx, _ := control.GetScanContext(control.Portscan) // 标识任务
	addresses := make(chan portscan.Address)

	// 先统计实际要扫描的总数
	totalCount := len(ips)*len(ports) + len(specialTargets)
	// 发送总数给前端
	runtime.EventsEmit(a.ctx, "portScanTotalCount", totalCount)

	go func() {
		defer close(addresses)
		// Generate addresses from ips and ports
		for _, ip := range ips {
			for _, port := range ports {
				addresses <- portscan.Address{IP: ip, Port: port}
			}
		}
		// Generate addresses from special targets
		for _, target := range specialTargets {
			temp := strings.Split(target, ":")
			port, err := strconv.Atoi(temp[1]) // Skip if port conversion fails
			if err != nil {
				continue
			}
			addresses <- portscan.Address{IP: temp[0], Port: port}
		}
	}()
	portscan.TcpScan(a.ctx, ctrlCtx, taskId, addresses, thread, timeout, proxyURL)
}

// 端口暴破
func (a *App) NewCrackScanenr(taskId, host string, usernames, passwords []string) {
	ctrlCtx, _ := control.GetScanContext(control.Crack) // 标识任务
	portscan.Runner(a.ctx, ctrlCtx, taskId, host, usernames, passwords)
}

// fofa

func (a *App) FofaTips(query string) *structs.TipsResult {
	config := space.NewFofaConfig(nil)
	b, err := config.GetTips(query)
	if err != nil {
		gologger.Debug(a.ctx, err)
		return nil
	}
	var ts structs.TipsResult
	json.Unmarshal(b, &ts)
	return &ts
}

func (a *App) FofaSearch(query, pageSzie, pageNum, address, email, key string, fraud, cert, withFid bool) *structs.FofaSearchResult {
	config := space.NewFofaConfig(&structs.FofaAuth{
		Address: address,
		Email:   email,
		Key:     key,
	})
	return config.FofaApiSearch(a.ctx, query, pageSzie, pageNum, fraud, cert, withFid)
}

func (a *App) Socks5Conn(ip string, port, timeout int, username, password, aliveURL string) bool {
	return portscan.Socks5Conn(ip, port, timeout, username, password, aliveURL)
}

func (a *App) IconHash(target string) string {
	resp, err := clients.SimpleGet(target, clients.NewRestyClient(nil, true))
	if err != nil {
		return ""
	}
	return webscan.Mmh3Hash32(resp.Body())
}

// 仅在执行时调用一次
func (a *App) InitRule(appendTemplateFolder string) bool {
	templateFolders := []string{a.templateDir, appendTemplateFolder}
	config := &webscan.Config{
		TemplateFolders:     templateFolders,
		ActiveRuleFile:      a.activefingerFile,
		FingerprintRuleFile: a.webfingerFile,
	}
	return config.InitAll(a.ctx)
}

// webscan

func (a *App) FingerprintList() []string {
	var fingers []string
	for _, item := range webscan.FingerprintDB {
		fingers = append(fingers, item.ProductName)
	}
	return fingers
}

// 多线程 Nuclei 扫描，由于Nucli的设计问题，多线程无法调用代理，否则会导致扫描失败
func (a *App) NewWebScanner(taskId string, options structs.WebscanOptions, proxyURL string, threadSafe bool) {
	ctrlCtx, cancel := control.GetScanContext(control.Webscan) // 标识任务
	defer cancel()
	webscan.IsRunning = true
	gologger.Info(a.ctx, fmt.Sprintf("Load web scanner, targets number: %d", len(options.Target)))
	gologger.Info(a.ctx, "Fingerscan is running ...")

	engine := webscan.NewWebscanEngine(a.ctx, taskId, proxyURL, options)
	if engine == nil {
		gologger.Error(a.ctx, "Init fingerscan engine failed")
		webscan.IsRunning = false
		return
	}

	// 指纹识别
	engine.FingerScan(ctrlCtx)
	if options.DeepScan && ctrlCtx.Err() == nil {
		engine.ActiveFingerScan(ctrlCtx)
	}

	if options.CallNuclei && ctrlCtx.Err() == nil {
		gologger.Info(a.ctx, "Init nuclei engine, vulnerability scan is running ...")

		// 准备模板目录
		var allTemplateFolders = []string{a.templateDir}
		if options.AppendTemplateFolder != "" {
			allTemplateFolders = append(allTemplateFolders, options.AppendTemplateFolder)
		}

		// 提取所有目标和标签
		fpm := engine.URLWithFingerprintMap()
		allOptions := []structs.NucleiOption{}
		for target, tags := range fpm {
			allOptions = append(allOptions, structs.NucleiOption{
				URL:                   target,
				Tags:                  arrayutil.RemoveDuplicates(tags),
				TemplateFile:          options.TemplateFiles,
				SkipNucleiWithoutTags: options.SkipNucleiWithoutTags,
				TemplateFolders:       allTemplateFolders,
				CustomTags:            options.Tags,
				CustomHeaders:         options.CustomHeaders,
				Proxy:                 proxyURL,
			})
		}
		counts := len(allOptions)
		if counts == 0 {
			gologger.Warning(a.ctx, "nuclei scan no targets")
			webscan.IsRunning = false
			return
		}
		runtime.EventsEmit(a.ctx, "NucleiCounts", counts)

		if threadSafe {
			webscan.NewThreadSafeNucleiEngine(a.ctx, ctrlCtx, taskId, allOptions)
		} else {
			webscan.NewNucleiEngine(a.ctx, ctrlCtx, taskId, allOptions)
		}

		gologger.Info(a.ctx, "Vulnerability scan has ended")
	}
	webscan.IsRunning = false
}

func (a *App) GetFingerPocMap() map[string][]string {
	return webscan.WorkFlowDB
}

// hunter

func (a *App) HunterTips(query string) *structs.HunterTips {
	return space.SearchHunterTips(query)
}

func (a *App) HunterSearch(api, key, query, pageSize, pageNum, times, asset string, deduplication bool) *structs.HunterResult {
	hr := space.HunterApiSearch(a.ctx, api, key, query, pageSize, pageNum, times, asset, deduplication)
	time.Sleep(time.Second * 2)
	return hr
}

// quake

func (a *App) QuakeTips(query string) *structs.QuakeTipsResult {
	return space.SearchQuakeTips(query)
}

func (a *App) QuakeSearch(ipList []string, query string, pageNum, pageSize int, latest, invalid, honeypot, cdn bool, token, certcommon string) *structs.QuakeResult {
	option := structs.QuakeRequestOptions{
		IpList:     ipList,
		Query:      query,
		PageNum:    pageNum,
		PageSize:   pageSize,
		Latest:     latest,
		Invalid:    invalid,
		Honeypot:   honeypot,
		CDN:        cdn,
		Token:      token,
		CertCommon: certcommon,
	}
	qk := space.QuakeApiSearch(&option)
	time.Sleep(time.Second * 1)
	return qk
}

func (a *App) ExtractAllJSLink(url string) []string {
	return jsfind.ExtractAllJs(a.ctx, url)
}

func (a *App) JSFind(target, prefixJsURL string, jsLinks, blackDomainList []string) structs.FindSomething {
	return jsfind.Scan(a.ctx, target, prefixJsURL, jsLinks, blackDomainList)
}

func (a *App) AnalyzeAPI(homeURL, baseURL string, apiList []string, headers, lowPrivilegeHeaders map[string]string, authentication []string, highRiskRouter []string) {
	options := structs.JSFindOptions{
		HomeURL:             homeURL,
		BaseURL:             baseURL,
		ApiList:             apiList,
		Headers:             headers,
		Authentication:      authentication,
		HighRiskRouter:      highRiskRouter,
		LowPrivilegeHeaders: lowPrivilegeHeaders,
	}
	jsfind.AnalyzeAPI(a.ctx, options)
}

// 允许目标传入文件或者目标favicon地址
func (a *App) FaviconMd5(target string) string {
	hasher := md5.New()
	if _, err := os.Stat(target); err != nil {
		resp, err := clients.SimpleGet(target, clients.NewRestyClient(nil, true))
		if err != nil {
			return ""
		}
		hasher.Write(resp.Body())
	} else {
		content, err := os.ReadFile(target)
		if err != nil {
			return ""
		}
		hasher.Write(content)
	}
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum)
}

func (a *App) UncoverSearch(query, types string, option structs.SpaceOption) []space.Result {
	return space.Uncover(a.ctx, query, types, option)
}

func (a *App) GitDorks(target, dork, apikey string) *structs.ISICollectionResult {
	return isic.GithubApiQuery(a.ctx, fmt.Sprintf("%s %s", target, dork), apikey)
}

func (a *App) GoogleHackerBingSearch(query string) *structs.ISICollectionResult {
	result, total, err := isic.GoogleHackerBingSearch(query)
	if err != nil {
		return nil
	}
	items := []string{}
	for _, item := range result {
		items = append(items, item.URL)
	}
	return &structs.ISICollectionResult{
		Items:  items,
		Link:   fmt.Sprintf("https://www.bing.com/search?q=%s", url.QueryEscape(query)),
		Source: "Bing",
		Total:  float64(total),
	}
}

func (a *App) NetDial(host string) bool {
	_, err := net.Dial("tcp", host)
	return err == nil
}

func (a *App) NewDSStoreEngine(url string) []string {
	url = strings.TrimSpace(url)
	links, err := dumpall.ExtractDSStore(url)
	if err != nil {
		gologger.Debug(a.ctx, err)
		return nil
	}
	return links
}

func (a *App) SendRequest(raw string, forceHttps, redirect bool, proxyURL string) structs.RawResponse {
	resp, t, err := repeater.SendRequestWithRaw(raw, forceHttps, redirect, proxyURL)
	if err != nil {
		if errors.Is(err, http.ErrUseLastResponse) {
			return structs.RawResponse{
				StatusCode:   0,
				Error:        "",
				Response:     string(httputil.DumpResponseHeadersOnly(resp.RawResponse)),
				ResponseTime: 0,
			}
		}
		return structs.RawResponse{
			StatusCode:   0,
			Error:        err.Error(),
			Response:     "",
			ResponseTime: 0,
		}
	}
	rawReponse, err := httputil.DumpResponseHeadersAndDecodedBody(resp.RawResponse)
	if err != nil {
		return structs.RawResponse{
			StatusCode:   resp.StatusCode(),
			Error:        err.Error(),
			Response:     "",
			ResponseTime: t,
		}
	}
	return structs.RawResponse{
		Error:        "",
		Response:     rawReponse,
		ResponseTime: t,
		StatusCode:   resp.StatusCode(),
	}
}
