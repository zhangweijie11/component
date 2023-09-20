package scraper

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/temoto/robotstxt"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type RodScraper struct {
	Browser *rod.Browser
	//Page                  *rod.Page
	pagePool              rod.PagePool
	PageSize              int
	TimeoutSeconds        int
	LoadingTimeoutSeconds int
	UserAgent             string
	protoUserAgent        *proto.NetworkSetUserAgentOverride
	lock                  *sync.RWMutex
	robotsMap             map[string]*robotstxt.RobotsData
	depth                 int
}

func (s *RodScraper) CanRenderPage() bool {
	return true
}

func (s *RodScraper) SetDepth(depth int) {
	s.depth = depth
}

func (s *RodScraper) Init() error {
	return rod.Try(func() {
		// 寻找可执行程序的路径
		path, _ := launcher.LookPath()
		u := launcher.New().Bin(path).NoSandbox(true).MustLaunch()
		s.lock = &sync.RWMutex{}
		s.robotsMap = make(map[string]*robotstxt.RobotsData)
		//允许使用给定字符串覆盖用户代理。
		s.protoUserAgent = &proto.NetworkSetUserAgentOverride{UserAgent: s.UserAgent}
		// 如果 ControlURL 未设置， MustConnect 将自动运行 launcher.New().MustLaunch()。 默认情况下，launcher 将自动下载并使用固定版本的浏览器，以保证浏览器 的行为一致性。
		// MustIgnoreCertErrors 忽略证书错误
		s.Browser = rod.New().ControlURL(u).MustConnect().MustIgnoreCertErrors(true)
		s.pagePool = createPagePool(s.PageSize)
	})
}

// 检查是否为 robots url， robots.txt 排除协议
func (s *RodScraper) checkRobots(u *url.URL) error {
	s.lock.RLock()
	robot, ok := s.robotsMap[u.Host]
	s.lock.RUnlock()

	if !ok {
		//InsecureSkipVerify 控制客户端是否验证服务器的证书链和主机名。如果 InsecureSkipVerify 为 true，则 cryptotls 接受服务器提供的任何证书以及该证书中的任何主机名。在此模式下，除非使用自定义验证，否则 TLS 容易受到中间计算机攻击。
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := &http.Client{Transport: tr}
		//拼接请求 robots.txt 路径
		resp, err := client.Get(u.Scheme + "://" + u.Host + "/robots.txt")
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		robot, err = robotstxt.FromResponse(resp)
		if err != nil {
			return err
		}

		s.lock.Lock()
		s.robotsMap[u.Host] = robot
		s.lock.Unlock()
	}

	uaGroup := robot.FindGroup(s.UserAgent)
	//将 URL 路径中的特殊字符进行转义
	eu := u.EscapedPath()

	if u.RawQuery != "" {
		eu += "?" + u.Query().Encode()
	}

	// 来自 Google 的规范：默认情况下，对指定的抓取工具的抓取没有任何限制。
	if !uaGroup.Test(eu) {
		return errors.New("无法获取 robot 文件")
	}

	return nil
}

// Scrape 请求页面并获取相关数据
func (s *RodScraper) Scrape(paramURL string) (*ScrapedData, interface{}, error) {
	scraped := &ScrapedData{}

	//根据传入的 URL重组为标准 URL 结构
	parsedURL, err := url.Parse(paramURL)
	if err != nil {
		return scraped, nil, err
	}

	//当递归深度大于 1 的时候需要检查是不是robots
	if s.depth > 0 {
		if err = s.checkRobots(parsedURL); err != nil {
			return scraped, nil, err
		}
	}

	//获取目标 URL的 DNS 解析数据
	scraped.DNS = scrapeDNS(paramURL)

	// 创建一个新的页面，不在当前方法中关闭页面是因为还需要在该页面加载 JS 代码
	page := s.GetPage()

	// 当 HTTP 响应可用时触发
	var e proto.NetworkResponseReceived
	wait := page.WaitEvent(&e)
	// 当页面上弹出警告框、确认框、提示框等对话框时，使用 MustHandleDialog 方法可以自动处理这些对话框
	go page.MustHandleDialog()

	//导航到该 URL 页面
	errRod := rod.Try(func() {
		page.Timeout(time.Duration(s.TimeoutSeconds) * time.Second).
			MustSetUserAgent(s.protoUserAgent).MustNavigate(paramURL)
	})
	if errRod != nil {
		return scraped, nil, errRod
	}

	// 等待页面响应
	wait()

	// 获取安全验证信息
	if e.Response.SecurityDetails != nil && len(e.Response.SecurityDetails.Issuer) > 0 {
		scraped.CertIssuer = append(scraped.CertIssuer, e.Response.SecurityDetails.Issuer)
	}

	// 获取响应状态码
	scraped.URL = e.Response.URL
	scraped.StatusCode = e.Response.Status

	// 获取响应头
	scraped.Headers = make(map[string][]string)
	for header, value := range e.Response.Headers {
		lowerCaseKey := strings.ToLower(header)
		scraped.Headers[lowerCaseKey] = append(scraped.Headers[lowerCaseKey], value.String())
	}

	// 获取页面源码
	html, errRod := page.HTML()
	if errRod == nil {
		scraped.HTML = html
	}

	// 获取标题
	info, errRod := page.Info()
	if errRod == nil {
		scraped.Title = info.Title
	}

	// 获取脚本
	scripts, _ := page.Elements("script")
	for _, script := range scripts {
		if src, _ := script.Property("src"); src.Val() != nil {
			scraped.Scripts = append(scraped.Scripts, src.String())
		}
	}

	// 获取 meta 信息
	metas, _ := page.Elements("meta")
	scraped.Meta = make(map[string][]string)
	for _, meta := range metas {
		name, _ := meta.Attribute("name")
		if name == nil {
			name, _ = meta.Attribute("property")
		}

		if name != nil {
			if content, _ := meta.Attribute("content"); content != nil {
				nameLower := strings.ToLower(*name)
				scraped.Meta[nameLower] = append(scraped.Meta[nameLower], *content)
			}
		}
	}

	// 获取 cookies
	scraped.Cookies = make(map[string]string)
	var str []string
	cookies, _ := page.Cookies(str)
	for _, cookie := range cookies {
		scraped.Cookies[cookie.Name] = cookie.Value
	}

	// 获取 Favicon
	favicon, faviconHash := getFavicon(scraped.HTML, paramURL)
	scraped.Favicon = favicon
	scraped.FaviconHash = faviconHash

	return scraped, page, nil
}

func (s *RodScraper) EvalJS(page interface{}, jsProp string) (*string, error) {
	// 避免加载 JS 时卡死导致无法释放资源，所以使用 ctx，保证操作会被取消从而释放资源
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	resCh := make(chan map[string]interface{})

	go func() {
		response, resErr := page.(*rod.Page).Eval(jsProp)
		resCh <- map[string]interface{}{
			"response": response,
			"resErr":   resErr,
		}
	}()

	select {
	case resMap := <-resCh:
		if resMap["resErr"] == nil {
			if resMap["response"] != nil && resMap["response"].(*proto.RuntimeRemoteObject).Value.Val() != nil {
				value := ""
				if resMap["response"].(*proto.RuntimeRemoteObject).Type == "string" || resMap["response"].(*proto.RuntimeRemoteObject).Type == "number" {
					value = resMap["response"].(*proto.RuntimeRemoteObject).Value.String()
				}
				return &value, nil
			}
		} else {
			return nil, resMap["resErr"].(error)
		}
	case <-ctx.Done():
		cancel()
		return nil, errors.New("EvalJS timeout")
	}

	return nil, nil
}

// GetBrowser 获得浏览器对象
func getBrowser(l *launcher.Launcher) *rod.Browser {
	u := l.MustLaunch()
	return rod.New().ControlURL(u).MustConnect().MustIgnoreCertErrors(true)

}

// createPage 生成一个page对象
func (s *RodScraper) createPage() (page *rod.Page) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.Browser == nil {
		// 寻找可执行程序的路径
		path, _ := launcher.LookPath()
		u := launcher.New().Bin(path).NoSandbox(true)
		s.Browser = getBrowser(u)
	}
	page = stealth.MustPage(s.Browser)
	return
}

// CreatePagePool 内部pagePool大小
func createPagePool(pageSize int) rod.PagePool {
	return rod.NewPagePool(pageSize)
}

func (s *RodScraper) GetPage() *rod.Page {
	s.lock.Lock()
	if s.pagePool == nil {
		s.pagePool = createPagePool(s.PageSize)
	}
	s.lock.Unlock()
	return s.pagePool.Get(s.createPage)
}

// PutPage 回收page
func (s *RodScraper) PutPage(pageInterface interface{}) {
	page := pageInterface.(*rod.Page)
	err := page.Navigate("about:blank")
	if err != nil {
		logger.Warn("回收页面出现问题")
	} else {
		s.pagePool.Put(page)
	}
}

// Close 关闭浏览器
func (s *RodScraper) Close() {
	if s.Browser != nil {
		pages, _ := s.Browser.Pages()
		for _, page := range pages {
			err := page.Close()
			if err != nil {
				logger.Warn("关闭页面出现问题")
				continue
			}
		}
		err := s.Browser.Close()
		if err != nil {
			logger.Error("关闭浏览器出现错误", err)
		}
	} else {
		logger.Warn("关闭浏览器出现错误，浏览器实例为 nil")
	}
}
