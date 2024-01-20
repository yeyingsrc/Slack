package poc

import (
	"os"
	"slack-wails/lib/util"
	"strings"

	"gopkg.in/yaml.v2"
)

// https://docs.xray.cool/#/guide/poc/v2
// Rule有序，参考：https://github.com/WAY29/pocV/blob/main/pkg/xray/structs/poc.go

const (
	STOP_IF_FIRST_MATCH    = "STOP_IF_FIRST_MATCH"
	STOP_IF_FIRST_MISMATCH = "STOP_IF_FIRST_MISMATCH"
)

type Poc struct {
	Id         string        `yaml:"id"`        //  脚本名称
	Transport  string        `yaml:"transport"` // 传输方式，该字段用于指定发送数据包的协议，该字段用于指定发送数据包的协议:①tcp ②udp ③http
	Set        yaml.MapSlice `yaml:"set"`       // 全局变量定义，该字段用于定义全局变量。比如随机数，反连平台等
	Payloads   Payloads      `yaml:"payloads"`
	Rules      RuleMapSlice  `yaml:"rules"`
	Expression string        `yaml:"expression"`
	Info       Info          `yaml:"info"`
	Gopoc      string        `yaml:"gopoc"` // Gopoc 脚本名称
	Extractors []Extractors  `yaml:"extractors"`
}

// TODO REMARK
type Payloads struct {
	Continue bool          `yaml:"continue"`
	Payloads yaml.MapSlice `yaml:"payloads"`
}

// 以下是 脚本部分
var order = 0

// 用于帮助yaml解析，保证Rule有序
type RuleMap struct {
	Key   string
	Value Rule
}

// 用于帮助yaml解析，保证Rule有序
type RuleMapSlice []RuleMap
type Rule struct {
	Brute          yaml.MapSlice `yaml:"brute"`
	Request        RuleRequest   `yaml:"request"`
	Expression     string        `yaml:"expression"`
	Expressions    []string      `yaml:"expressions"`
	Output         yaml.MapSlice `yaml:"output"`
	Extractors     []Extractors  `yaml:"extractors"`
	StopIfMatch    bool          `yaml:"stop_if_match"`
	StopIfMismatch bool          `yaml:"stop_if_mismatch"`
	BeforeSleep    int           `yaml:"before_sleep"`
	order          int
}

// http/tcp/udp cache 是否使用缓存的请求，如果该选项为 true，那么如果在一次探测中其它脚本对相同目标发送过相同请求，那么便使用之前缓存的响应，而不发新的数据包
// content 用于tcp/udp请求，请求内容，比如：content: "request"
// read_timeout 用于tcp/udp请求，发送请求之后的读取超时时间（注 实际是一个 int， 但是为了能够变量渲染，设置为 string）
type RuleRequest struct {
	Type            string            `yaml:"type"`         // 传输方式，默认 http，可选：tcp,udp,ssl,go 等任意扩展
	Host            string            `yaml:"host"`         // tcp/udp 请求的主机名
	Data            string            `yaml:"data"`         // tcp/udp 发送的内容
	DataType        string            `yaml:"data-type"`    // tcp/udp 发送的数据类型，默认字符串
	ReadSize        int               `yaml:"read-size"`    // tcp/udp 读取内容的长度
	ReadTimeout     int               `yaml:"read-timeout"` // tcp/udp专用
	Raw             string            `yaml:"raw"`          // raw 专用
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
}

const (
	HTTP_Type = "http"
	TCP_Type  = "tcp"
	UDP_Type  = "udp"
	SSL_Type  = "ssl"
	GO_Type   = "go"
)

// 以下开始是 信息部分
type Info struct {
	Name           string         `yaml:"name"`
	Author         string         `yaml:"author"`
	Severity       string         `yaml:"severity"`
	Verified       bool           `yaml:"verified"`
	Description    string         `yaml:"description"`
	Reference      []string       `yaml:"reference"`
	Affected       string         `yaml:"affected"`  // 影响版本
	Solutions      string         `yaml:"solutions"` // 解决方案
	Tags           string         `yaml:"tags"`      // 标签
	Classification Classification `yaml:"classification"`
	Created        string         `yaml:"created"` // create time
}

type Classification struct {
	CvssMetrics string  `yaml:"cvss-metrics"`
	CvssScore   float64 `yaml:"cvss-score"`
	CveId       string  `yaml:"cve-id"`
	CweId       string  `yaml:"cwe-id"`
}

// 不可删除
type ruleAlias struct {
	Brute          yaml.MapSlice `yaml:"brute"`
	Request        RuleRequest   `yaml:"request"`
	Expression     string        `yaml:"expression"`
	Expressions    []string      `yaml:"expressions"`
	Output         yaml.MapSlice `yaml:"output"`
	Extractors     []Extractors  `yaml:"extractors"`
	StopIfMatch    bool          `yaml:"stop_if_match"`
	StopIfMismatch bool          `yaml:"stop_if_mismatch"`
	BeforeSleep    int           `yaml:"before_sleep"`
}

type VulnerabilityDetails struct {
	Name        string
	Risk        string
	Author      string
	Tags        string
	Description string
	Reference   string
	Affected    string
	Solutions   string
}

var pocsWorkflower = util.ExecutionPath() + "/config/workflow.yaml"

// 输入目标指纹，返回对应指纹的POC路径
func FingerPocFilepath(fingerpirnts []string) ([]string, error) {
	files := []string{}
	data := make(map[string][]string)
	yamlData, err := os.ReadFile(pocsWorkflower)
	if err != nil {
		return files, err
	}
	err = yaml.Unmarshal(yamlData, &data)
	for finger, pocpath := range data {
		for _, f := range fingerpirnts {
			if strings.EqualFold(finger, f) {
				files = append(files, pocpath...)
			}
		}
	}
	return files, err
}

// Read a poc yaml file from disk.
// `pocYaml` is a poc yaml file of absolute path.
func LocalReadPocByPath(pocYaml string) (Poc, error) {
	var poc = Poc{}
	b, err := os.ReadFile(pocYaml)
	if err != nil {
		return poc, err
	}
	if err := yaml.Unmarshal(b, &poc); err != nil {
		return poc, err
	}
	return poc, nil
}

// 不可删除
func (r *Rule) UnmarshalYAML(unmarshal func(any) error) error {
	var tmp ruleAlias
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	r.Brute = tmp.Brute
	r.Request = tmp.Request
	r.Expression = tmp.Expression
	r.Expressions = append(r.Expressions, tmp.Expressions...)
	r.Output = tmp.Output
	r.Extractors = append(r.Extractors, tmp.Extractors...)
	r.StopIfMatch = tmp.StopIfMatch
	r.StopIfMismatch = tmp.StopIfMismatch
	r.BeforeSleep = tmp.BeforeSleep
	r.order = order

	order += 1
	return nil
}

// 不可删除
func (m *RuleMapSlice) UnmarshalYAML(unmarshal func(any) error) error {
	order = 0

	tempMap := make(map[string]Rule, 1)
	err := unmarshal(&tempMap)
	if err != nil {
		return err
	}

	newRuleSlice := make([]RuleMap, len(tempMap))
	for roleName, role := range tempMap {
		newRuleSlice[role.order] = RuleMap{
			Key:   roleName,
			Value: role,
		}
	}

	*m = RuleMapSlice(newRuleSlice)
	return nil
}

// 重置器
func (poc *Poc) Reset() {
	poc.Id = ""
	poc.Transport = ""
	poc.Set = nil
	poc.Payloads = Payloads{}
	poc.Rules = nil
	poc.Expression = ""
	poc.Info = Info{}
}

func (poc *Poc) IsHTTPType() bool {
	for _, rule := range poc.Rules {
		reqType := rule.Value.Request.Type
		if len(reqType) == 0 || reqType == HTTP_Type {
			return true
		}
	}
	return false
}

func (poc *Poc) IsReverse() bool {
	if len(poc.Set) == 0 {
		return false
	}
	for _, set := range poc.Set {
		k, v := set.Key.(string), set.Value.(string)
		if strings.Contains(k, "reverse") || strings.Contains(v, "reverse.url") {
			return true
		}
	}
	return false
}

// 拓展输出
type Extractors struct {
	Type      string        `yaml:"type"`      // regex,str
	Extractor yaml.MapSlice `yaml:"extractor"` //
}
