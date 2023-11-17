package scraper

import (
	"crypto/tls"
	"errors"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"gitlab.example.com/zhangweijie/component/services/certificate"
	"net"
	"net/http"
	"strings"
	"time"
)

// CollyScraper colly 抓取结构
type CollyScraper struct {
	Collector             *colly.Collector
	Transport             *http.Transport
	Response              *http.Response
	TimeoutSeconds        int
	LoadingTimeoutSeconds int
	UserAgent             string
	depth                 int
}

type GoWapTransport struct {
	*http.Transport
	respCallBack func(resp *http.Response)
}

func NewGoWapTransport(t *http.Transport, f func(resp *http.Response)) *GoWapTransport {
	return &GoWapTransport{t, f}
}

// Init 初始化 colly 抓取
func (s *CollyScraper) Init() error {
	s.Transport = &http.Transport{
		//用于创建未加密的TCP连接
		DialContext: (&net.Dialer{
			Timeout: time.Second * time.Duration(s.TimeoutSeconds),
		}).DialContext,
		//控制所有主机的最大空闲（保持活动）连接数。零表示没有限制。
		MaxIdleConns: 100,
		//空闲（保持活动状态）连接在关闭自身之前保持空闲的最长时间。零表示没有限制。
		IdleConnTimeout: 90 * time.Second,
		//等待 TLS 握手的最长时间。零表示无超时。
		TLSHandshakeTimeout: 2 * time.Second,
		//如果非零，则指定在完全写入请求标头后等待服务器的第一个响应标头的时间量（如果请求具有“预期：100-continue”标头）。零表示没有超时，并导致正文立即发送，而无需等待服务器批准。此时间不包括发送请求标头的时间。
		ExpectContinueTimeout: time.Duration(s.TimeoutSeconds) * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	s.Collector = colly.NewCollector()
	s.Collector.UserAgent = s.UserAgent

	setResp := func(r *http.Response) {
		s.Response = r
	}

	//自定义传输
	s.Collector.WithTransport(NewGoWapTransport(s.Transport, setResp))

	// 为请求设置有效的 Referer HTTP 标头。警告：仅当使用 Request.Visit from 回调而不是 Collector.Visit 时，此扩展才有效。
	extensions.Referer(s.Collector)

	return nil
}

func (s *CollyScraper) CanRenderPage() bool {
	return false
}

func (s *CollyScraper) SetDepth(depth int) {
	s.depth = depth
}

func (gt *GoWapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rsp, err := gt.Transport.RoundTrip(req)
	gt.respCallBack(rsp)
	return rsp, err
}

// Scrape 抓取流程
func (s *CollyScraper) Scrape(paramURL string) (*ScrapedData, interface{}, error) {
	scraped := &ScrapedData{}
	// 获取 DNS 解析数据
	scraped.DNS = scrapeDNS(paramURL)

	if s.depth > 0 {
		s.Collector.IgnoreRobotsTxt = false
	}

	s.Collector.OnResponse(func(r *colly.Response) {
		// 获取响应状态码
		if r.Request != nil {
			scraped.URL = r.Request.URL.String()
		}
		if r.StatusCode != 0 {
			scraped.StatusCode = r.StatusCode
		}

		// 获取响应头数据
		scraped.Headers = make(map[string][]string)
		if r.Headers != nil {
			for key, value := range *r.Headers {
				lowerCaseKey := strings.ToLower(key)
				scraped.Headers[lowerCaseKey] = value
			}
		}

		if r.Body != nil {
			// 获取源码
			scraped.HTML = string(r.Body)
		}

		// 获取 cookies
		scraped.Cookies = make(map[string]string)
		for _, cookie := range scraped.Headers["set-cookies"] {
			keyValues := strings.Split(cookie, ";")
			for _, keyValueString := range keyValues {
				keyValueSlice := strings.Split(keyValueString, "=")
				if len(keyValueSlice) > 1 {
					key, value := keyValueSlice[0], keyValueSlice[1]
					scraped.Cookies[key] = value
				}
			}
		}
		if s.Response != nil && s.Response.TLS != nil && len(s.Response.TLS.PeerCertificates) > 0 {
			// 获取证书信息
			certInfo := certificate.GetCertInfoOfResponse(s.Response)
			scraped.Certificate = certInfo
			if len(s.Response.TLS.PeerCertificates[0].Issuer.Organization) > 0 {
				scraped.CertIssuer = append(scraped.CertIssuer, s.Response.TLS.PeerCertificates[0].Issuer.Organization...)
			}
			if len(s.Response.TLS.PeerCertificates[0].Issuer.CommonName) > 0 {
				scraped.CertIssuer = append(scraped.CertIssuer, s.Response.TLS.PeerCertificates[0].Issuer.CommonName)
			}
		}
	})
	s.Collector.OnError(func(r *colly.Response, err error) {
		// 获取响应状态码
		if r.Request != nil {
			scraped.URL = r.Request.URL.String()
		}
		if r.StatusCode != 0 {
			scraped.StatusCode = r.StatusCode
		}

		// 获取响应头数据
		scraped.Headers = make(map[string][]string)
		if r.Headers != nil {
			for key, value := range *r.Headers {
				lowerCaseKey := strings.ToLower(key)
				scraped.Headers[lowerCaseKey] = value
			}
		}
		if r.Body != nil {
			// 获取源码
			scraped.HTML = string(r.Body)
		}

		// 获取 cookies
		scraped.Cookies = make(map[string]string)
		for _, cookie := range scraped.Headers["set-cookies"] {
			keyValues := strings.Split(cookie, ";")
			for _, keyValueString := range keyValues {
				keyValueSlice := strings.Split(keyValueString, "=")
				if len(keyValueSlice) > 1 {
					key, value := keyValueSlice[0], keyValueSlice[1]
					scraped.Cookies[key] = value
				}
			}
		}
		if s.Response != nil && s.Response.TLS != nil && len(s.Response.TLS.PeerCertificates) > 0 {
			if len(s.Response.TLS.PeerCertificates[0].Issuer.Organization) > 0 {
				scraped.CertIssuer = append(scraped.CertIssuer, s.Response.TLS.PeerCertificates[0].Issuer.Organization...)
			}
			if len(s.Response.TLS.PeerCertificates[0].Issuer.CommonName) > 0 {
				scraped.CertIssuer = append(scraped.CertIssuer, s.Response.TLS.PeerCertificates[0].Issuer.CommonName)
			}
		}
	})
	// 获取脚本
	s.Collector.OnHTML("script", func(e *colly.HTMLElement) {
		scraped.Scripts = append(scraped.Scripts, e.Attr("src"))
	})

	// 获取 title
	s.Collector.OnHTML("title", func(e *colly.HTMLElement) {
		scraped.Title = e.Text
	})

	// 设置超时时间
	s.Collector.SetRequestTimeout(time.Duration(s.TimeoutSeconds) * time.Second)
	s.Collector.Visit(paramURL)

	// 获取 Favicon
	favicon, faviconHash := getFavicon(scraped.HTML, paramURL)
	scraped.Favicon = favicon
	scraped.FaviconHash = faviconHash

	return scraped, nil, nil
}

// EvalJS 执行 JS
func (s *CollyScraper) EvalJS(page interface{}, jsProp string) (*string, error) {
	return nil, errors.New("未实现")
}

func (s *CollyScraper) Close() {
	return
}
