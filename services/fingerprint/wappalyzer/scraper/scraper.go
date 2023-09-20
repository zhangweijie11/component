package scraper

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/spaolacci/murmur3"
	"gitlab.example.com/zhangweijie/component/services/certificate"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ScrapedData 请求数据
type ScrapedData struct {
	URL         string
	StatusCode  int
	Title       string
	HTML        string
	Headers     map[string][]string
	Scripts     []string
	Cookies     map[string]string
	Meta        map[string][]string
	DNS         map[string][]string
	CertIssuer  []string
	Favicon     string
	FaviconHash string
	Certificate *certificate.Certificate
}

// Scraper 爬取接口
type Scraper interface {
	// Init 初始化
	Init() error
	// CanRenderPage 是否进行 JS渲染页面
	CanRenderPage() bool
	// Scrape 爬取页面
	Scrape(paramURL string) (*ScrapedData, interface{}, error)
	// EvalJS 执行 JS
	EvalJS(page interface{}, jsProp string) (*string, error)
	// SetDepth 设置递归深度
	SetDepth(depth int)
	// Close 关闭浏览器
	Close()
}

// scrapeDNS 获取 DNS 数据
func scrapeDNS(paramURL string) map[string][]string {
	scrapedDNS := make(map[string][]string)
	u, _ := url.Parse(paramURL)
	parts := strings.Split(u.Hostname(), ".")
	domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
	nsSlice, _ := net.LookupNS(domain)
	for _, ns := range nsSlice {
		scrapedDNS["NS"] = append(scrapedDNS["NS"], ns.Host)
	}
	mxSlice, _ := net.LookupMX(domain)
	for _, mx := range mxSlice {
		scrapedDNS["MX"] = append(scrapedDNS["MX"], mx.Host)
	}

	txtSlice, _ := net.LookupTXT(domain)
	scrapedDNS["TXT"] = append(scrapedDNS["TXT"], txtSlice...)
	cname, _ := net.LookupCNAME(domain)
	scrapedDNS["CNAME"] = append(scrapedDNS["CNAME"], cname)

	return scrapedDNS

}

// 获取 favicon 数据
func getFavicon(response string, paramUrl string) (string, string) {
	faviconReg := regexp.MustCompile(`href="(.*?favicon....)"`)
	faviconRegResult := faviconReg.FindAllStringSubmatch(response, -1)
	var faviconPath string
	u, err := url.Parse(paramUrl)
	if err != nil {
		logger.Warn("获取 favicon 出现错误")
	}
	paramUrl = u.Scheme + "://" + u.Host
	if len(faviconRegResult) > 0 {
		fav := faviconRegResult[0][1]
		if fav[:2] == "//" {
			faviconPath = "http:" + fav
		} else {
			if fav[:4] == "http" {
				faviconPath = fav
			} else {
				faviconPath = paramUrl + "/" + fav
			}

		}
	} else {
		faviconPath = paramUrl + "/favicon.ico"
	}
	return getFaviconHash(faviconPath)
}

// Hash favicon 数据
func hashFavicon(favicon []byte) (string, string) {
	stdBase64 := base64.StdEncoding.EncodeToString(favicon)
	stdBase64 = insertInto(stdBase64, 76, '\n')
	hasher := murmur3.New32WithSeed(0)
	hasher.Write([]byte(stdBase64))
	return stdBase64, fmt.Sprintf("%d", int32(hasher.Sum32()))
}

// 在某个位置插入数据
func insertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}

// 获取 favicon 和 favicon Hash 数据
func getFaviconHash(host string) (string, string) {
	timeout := 8 * time.Second
	var tr *http.Transport
	tr = &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
	}

	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse /* 不进入重定向 */
		},
	}
	resp, err := client.Get(host)
	if err != nil {
		logger.Warn("请求图标发生错误")
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		favicon, _ := io.ReadAll(resp.Body)

		faviconBase64, faviconHash := hashFavicon(favicon)
		return faviconBase64, faviconHash
	}
	return "", ""
}
