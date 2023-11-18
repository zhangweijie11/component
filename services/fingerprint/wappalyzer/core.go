package wappalyzer

import (
	"embed"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	jsoniter "github.com/json-iterator/go"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer/scraper"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"go.zoe.im/surferua"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config 整体配置项
type Config struct {
	AppsJSONPath           string //指纹库文件路径
	TimeoutSeconds         int    //访问超时
	LoadingTimeoutSeconds  int    //加载超时
	JSON                   bool   //是否 json 输出
	Scraper                string //页面抓取方式
	MaxDepth               int    //最大递归深度
	visitedLinks           int    //关联链接
	MaxVisitedLinks        int    //最大关联链接
	MsDelayBetweenRequests int    //页面访问延迟
	UserAgent              string //请求页面使用的 UA
	PageSize               int
}

// category 产品类别
type category struct {
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// ExtendedCategory 产品类别
type ExtendedCategory struct {
	ID       int    `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Priority int    `json:"-"`
}

type temp struct {
	Apps       map[string]*jsoniter.RawMessage `json:"technologies"`
	Categories map[string]*jsoniter.RawMessage `json:"categories"`
}

// application 应用数据
type application struct {
	Slug       string
	Name       string             `json:"name,omitempty"`
	Version    string             `json:"version"`
	Categories []ExtendedCategory `json:"categories,omitempty"`
	Icon       string             `json:"icon,omitempty"`
	Website    string             `json:"website,omitempty"`
	CPE        string             `json:"cpe,omitempty"`

	Cats       []int       `json:"cats,omitempty"`
	Cookies    interface{} `json:"cookies,omitempty"`
	Dom        interface{} `json:"dom,omitempty"`
	Js         interface{} `json:"js,omitempty"`
	Headers    interface{} `json:"headers,omitempty"`
	HTML       interface{} `json:"html,omitempty"`
	Excludes   interface{} `json:"excludes,omitempty"`
	Implies    interface{} `json:"implies,omitempty"`
	Meta       interface{} `json:"meta,omitempty"`
	Scripts    interface{} `json:"scripts,omitempty"`
	DNS        interface{} `json:"dns,omitempty"`
	URL        string      `json:"url,omitempty"`
	CertIssuer string      `json:"certIssuer,omitempty"`
}

// Wappalyzer Wappalyzer配置
type Wappalyzer struct {
	Scraper    scraper.Scraper
	Apps       map[string]*application
	Categories map[string]*ExtendedCategory
	Config     *Config
}

type pattern struct {
	str        string
	regex      *regexp.Regexp
	version    string
	confidence int
}

//go:embed assets/technologies.json
var f embed.FS
var embedPath = "assets/technologies.json"

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func NewWappalyzerScraper(wappalyzer *Wappalyzer, validScraper string) (err error) {
	switch validScraper {
	case "colly":
		wappalyzer.Scraper = &scraper.CollyScraper{
			TimeoutSeconds:        wappalyzer.Config.TimeoutSeconds,
			LoadingTimeoutSeconds: wappalyzer.Config.LoadingTimeoutSeconds,
			UserAgent:             wappalyzer.Config.UserAgent,
		}
		err = wappalyzer.Scraper.Init()
	case "rod":
		wappalyzer.Scraper = &scraper.RodScraper{
			TimeoutSeconds:        wappalyzer.Config.TimeoutSeconds,
			LoadingTimeoutSeconds: wappalyzer.Config.LoadingTimeoutSeconds,
			UserAgent:             wappalyzer.Config.UserAgent,
			PageSize:              wappalyzer.Config.PageSize,
		}
		err = wappalyzer.Scraper.Init()
	default:
		err = errors.New("未知爬取模型")
	}
	if err != nil {
		return err
	}

	return nil
}

func NewWappalyzer(maxDepth int, userAgent string) (wapp *Wappalyzer, err error) {
	config := &Config{
		AppsJSONPath:           "",
		TimeoutSeconds:         5,
		LoadingTimeoutSeconds:  5,
		PageSize:               10, // 单个浏览器实例最多能打开的页面数量
		MaxDepth:               maxDepth,
		visitedLinks:           0,
		MaxVisitedLinks:        10,
		MsDelayBetweenRequests: 100,
		UserAgent:              surferua.New().Desktop().Chrome().String(),
	}
	if userAgent != "" {
		config.UserAgent = userAgent
	}

	wapp = &Wappalyzer{Config: config}

	var appsFile []byte
	if config.AppsJSONPath != "" {
		appsFile, err = os.ReadFile(config.AppsJSONPath)
		if err != nil {
			return nil, err
		}
	}

	if config.AppsJSONPath == "" || len(appsFile) == 0 {
		//使用只读模式读取文件
		appsFile, err = f.ReadFile(embedPath)
		if err != nil {
			return nil, err
		}
	}
	err = parseTechnologiesFile(&appsFile, wapp)
	return wapp, err
}

// parseTechnologiesFile 解析Technologies文件
func parseTechnologiesFile(appsFile *[]byte, wapp *Wappalyzer) error {
	temporary := &temp{}
	err := json.Unmarshal(*appsFile, &temporary)
	if err != nil {
		logger.Error("无法序列化 technologies.json 文件", err)
		return err
	}
	wapp.Apps = make(map[string]*application)
	wapp.Categories = make(map[string]*ExtendedCategory)
	for k, v := range temporary.Categories {
		catg := &category{}
		if err = json.Unmarshal(*v, catg); err != nil {
			logger.Error("无法序列化产品类别", err)
			return err
		}
		catID, err := strconv.Atoi(k)
		if err == nil {
			slug, err := slugify(catg.Name)
			if err == nil {
				extCatg := &ExtendedCategory{catID, slug, catg.Name, catg.Priority}
				wapp.Categories[k] = extCatg
			}
		}
	}
	if len(wapp.Categories) < 1 {
		return errors.New("无法加载指纹库产品类别数据")
	}
	for k, v := range temporary.Apps {
		app := &application{}
		app.Name = k
		if err = json.Unmarshal(*v, app); err != nil {
			return err
		}
		parseCategories(app, &wapp.Categories)
		app.Slug, err = slugify(app.Name)
		wapp.Apps[k] = app
	}
	if len(wapp.Apps) < 1 {
		return errors.New("无法加载指纹库产品数据")
	}
	return err
}

// 解析产品类别
func parseCategories(app *application, categoriesCatalog *map[string]*ExtendedCategory) {
	for _, categoryID := range app.Cats {
		app.Categories = append(app.Categories, *(*categoriesCatalog)[strconv.Itoa(categoryID)])
	}
}

// 从输入字符串返回 slug 字符串， 例如 "Vue.js",输出为"vue-js"
func slugify(str string) (ret string, err error) {
	ret = strings.ToLower(str)
	reg, err := regexp.Compile(`[^a-z0-9-]`)
	if err == nil {
		ret = reg.ReplaceAllString(ret, "-")
		reg, err = regexp.Compile(`--+`)
		if err == nil {
			ret = reg.ReplaceAllString(ret, "-")
			reg, err = regexp.Compile(`(?:^-|-$)`)
			ret = reg.ReplaceAllString(ret, "")
		}
	}
	return ret, err
}

type Technology struct {
	Slug       string             `json:"slug"`       // 统一名称格式
	Name       string             `json:"name"`       // 名称
	Confidence int                `json:"confidence"` // 置信度
	Version    string             `json:"version"`    // 版本
	Icon       string             `json:"icon"`       // icon
	Website    string             `json:"website"`    // 官网
	CPE        string             `json:"cpe"`        // cpe
	Categories []ExtendedCategory `json:"categories"` // 类别列表
}

type resultApp struct {
	technology Technology  // 产品
	excludes   interface{} // 需要排除的产品
	implies    interface{} // 该产品依赖的产品
}

// 检测到的结果
type detected struct {
	Mu   *sync.Mutex
	Apps map[string]*resultApp
}

type WappFingerResult struct {
	ResponseData scraper.ScrapedData
	Technologies []Technology
}

// validateURL 校验 URL 的有效性
func validateURL(paramURL string) bool {
	regex, err := regexp.Compile(`^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$`)
	ret := false
	if err == nil {
		ret = regex.MatchString(paramURL)
	}
	return ret
}

// getLinksSlice 获取可跳转链接
func getLinksSlice(doc *goquery.Document, currentURL string) *map[string]struct{} {
	ret := make(map[string]struct{})
	parsedCurrentURL, _ := url.Parse(currentURL)
	var protocolRegex = regexp.MustCompile(`^https?`)

	doc.Find("body a").Each(func(index int, item *goquery.Selection) {
		rawLink, exists := item.Attr("href")
		if exists {
			parsedLink, err := url.Parse(rawLink)
			if err == nil {
				//如果未获取到协议，则使用当前 URL 的协议
				if parsedLink.Scheme == "" {
					parsedLink.Scheme = parsedCurrentURL.Scheme
				}
				//如果匹配到协议，并且跳转链接主机和当前 URL的主机相同，则组装好后添加到返回值中
				if matched := protocolRegex.MatchString(parsedLink.Scheme); matched && (parsedLink.Host == "" || parsedLink.Host == parsedCurrentURL.Host) {
					if strings.Trim(parsedLink.Path, "/") != "" {
						ret[parsedLink.Scheme+"://"+parsedCurrentURL.Host+"/"+strings.Trim(parsedLink.Path, "/")] = struct{}{}
					} else {
						ret[parsedLink.Scheme+"://"+parsedCurrentURL.Host] = struct{}{}
					}
				}
			}
		}
	})
	return &ret
}

// parsePatterns 解析规则
func parsePatterns(patterns interface{}) (result map[string][]*pattern) {
	parsed := make(map[string][]string)
	switch ptrn := patterns.(type) {
	case string:
		parsed["main"] = append(parsed["main"], ptrn)
	case map[string]interface{}:
		for k, v := range ptrn {
			switch content := v.(type) {
			case string:
				parsed[k] = append(parsed[k], v.(string))
			case []interface{}:
				for _, v1 := range content {
					parsed[k] = append(parsed[k], v1.(string))
				}
			default:
				logger.Warn("指纹识别解析未知类型")
			}
		}
	case []interface{}:
		var slice []string
		for _, v := range ptrn {
			slice = append(slice, v.(string))
		}
		parsed["main"] = slice
	default:
		logger.Warn("指纹识别解析未知类型")
	}

	result = make(map[string][]*pattern)
	for k, v := range parsed {
		for _, str := range v {
			appPattern := &pattern{confidence: 100}
			slice := strings.Split(str, "\\;")
			for i, item := range slice {
				if item == "" {
					continue
				}
				if i > 0 {
					additional := strings.SplitN(item, ":", 2)
					if len(additional) > 1 {
						if additional[0] == "version" {
							appPattern.version = additional[1]
						} else if additional[0] == "confidence" {
							appPattern.confidence, _ = strconv.Atoi(additional[1])
						}
					}
				} else {
					appPattern.str = item
					first := strings.Replace(item, `\/`, `/`, -1)
					second := strings.Replace(first, `\\`, `\`, -1)
					reg, err := regexp.Compile(fmt.Sprintf("%s%s", "(?i)", strings.Replace(second, `/`, `\/`, -1)))
					if err == nil {
						appPattern.regex = reg
					}
				}
			}
			result[k] = append(result[k], appPattern)
		}
	}

	return result
}

// detectVersion 检测到应用时尝试从值中提取版本
func detectVersion(pattrn *pattern, value *string) (res string) {
	if pattrn.regex == nil {
		return ""
	}
	versions := make(map[string]interface{})
	version := pattrn.version
	if slices := pattrn.regex.FindAllStringSubmatch(*value, -1); slices != nil {
		for _, slice := range slices {
			for i, match := range slice {
				reg, _ := regexp.Compile(fmt.Sprintf("%s%d%s", "\\\\", i, "\\?([^:]+):(.*)$"))
				ternary := reg.FindStringSubmatch(version)
				if len(ternary) == 3 {
					if match != "" {
						version = strings.Replace(version, ternary[0], ternary[1], -1)
					} else {
						version = strings.Replace(version, ternary[0], ternary[2], -1)
					}
				}
				reg2, _ := regexp.Compile(fmt.Sprintf("%s%d", "\\\\", i))
				version = reg2.ReplaceAllString(version, match)
			}
		}
		if _, ok := versions[version]; !ok && version != "" {
			versions[version] = struct{}{}
		}
		if len(versions) != 0 {
			for ver := range versions {
				if ver > res {
					res = ver
				}
			}
		}
	}
	return res
}

// addApp 将检测到的应用程序添加到结果列表， 如果已检测到该应用程序，我们将合并它（版本、置信度等）
func addApp(app *application, detectedApplications *detected, version string, confidence int) {
	detectedApplications.Mu.Lock()
	if _, ok := (*detectedApplications).Apps[app.Name]; !ok {
		resApp := &resultApp{Technology{app.Slug, app.Name, confidence, version, app.Icon, app.Website, app.CPE, app.Categories}, app.Excludes, app.Implies}
		(*detectedApplications).Apps[resApp.technology.Name] = resApp
	} else {
		if (*detectedApplications).Apps[app.Name].technology.Version == "" {
			(*detectedApplications).Apps[app.Name].technology.Version = version
		}
		if confidence > (*detectedApplications).Apps[app.Name].technology.Confidence {
			(*detectedApplications).Apps[app.Name].technology.Confidence = confidence
		}
	}
	detectedApplications.Mu.Unlock()
}

// analyzeURL 分析 URL 尝试匹配
func analyzeURL(app *application, paramURL string, detectedApplications *detected) {
	patterns := parsePatterns(app.URL)
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil && pattrn.regex.MatchString(paramURL) {
				version := detectVersion(pattrn, &paramURL)
				addApp(app, detectedApplications, version, pattrn.confidence)
			}
		}
	}
}

// analyzeJS 分析 JS 属性并尝试匹配
func analyzeJS(page interface{}, app *application, scraper scraper.Scraper, detectedApplications *detected) {
	patterns := parsePatterns(app.Js)
	for jsProp, v := range patterns {
		value, err := scraper.EvalJS(page, jsProp)
		if err == nil && value != nil {
			for _, pattrn := range v {
				if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(*value)) {
					version := detectVersion(pattrn, value)
					addApp(app, detectedApplications, version, pattrn.confidence)
				}
			}
		}
	}
}

// analyzeDom 分析 DOM 尝试匹配
func analyzeDom(app *application, doc *goquery.Document, detectedApplications *detected) {
	//Parsing Dom selector from json (string or map)
	domParsed := make(map[string]map[string]interface{})
	switch doms := app.Dom.(type) {
	case string:
		domParsed[doms] = map[string]interface{}{"exists": ""}
	case map[string]interface{}:
		for domSelector, v1 := range doms {
			domParsed[domSelector] = v1.(map[string]interface{})
		}
	case []interface{}:
		for _, domSelector := range doms {
			domParsed[domSelector.(string)] = map[string]interface{}{"exists": ""}
		}
	default:
		logger.Warn("指纹识别解析未知类型")
	}

	for domSelector, v1 := range domParsed {
		doc.Find(domSelector).First().Each(func(i int, s *goquery.Selection) {
			for domType, v := range v1 {
				patterns := parsePatterns(v)
				for attribute, pattrns := range patterns {
					for _, pattrn := range pattrns {
						var value string
						var exists bool
						switch domType {
						case "text", "exists":
							value = s.Text()
							exists = true
						case "properties":
							// Not implemented, should be done into the browser to get element properties
						case "attributes":
							value, exists = s.Attr(attribute)
						}
						if exists && pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(value)) {
							version := detectVersion(pattrn, &value)
							addApp(app, detectedApplications, version, pattrn.confidence)
						}
					}
				}
			}
		})
	}
}

// analyzeHTML 分析 HTML 尝试匹配
func analyzeHTML(app *application, html string, detectedApplications *detected) {
	patterns := parsePatterns(app.HTML)
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil && pattrn.regex.MatchString(html) {
				version := detectVersion(pattrn, &html)
				addApp(app, detectedApplications, version, pattrn.confidence)
			}
		}

	}
}

// analyzeHeaders 分析 Headers 尝试匹配
func analyzeHeaders(app *application, headers map[string][]string, detectedApplications *detected) {
	patterns := parsePatterns(app.Headers)
	for headerName, v := range patterns {
		headerNameLowerCase := strings.ToLower(headerName)
		for _, pattrn := range v {
			if headersSlice, ok := headers[headerNameLowerCase]; ok {
				for _, header := range headersSlice {
					if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(header)) {
						version := detectVersion(pattrn, &header)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

// analyzeCookies 分析 cookies 尝试匹配
func analyzeCookies(app *application, cookies map[string]string, detectedApplications *detected) {
	patterns := parsePatterns(app.Cookies)
	for cookieName, v := range patterns {
		cookieNameLowerCase := strings.ToLower(cookieName)
		for _, pattrn := range v {
			if cookie, ok := cookies[cookieNameLowerCase]; ok {
				if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(cookie)) {
					version := detectVersion(pattrn, &cookie)
					addApp(app, detectedApplications, version, pattrn.confidence)
				}
			}
		}
	}
}

// analyzeScripts 分析 scripts 尝试匹配
func analyzeScripts(app *application, scripts []string, detectedApplications *detected) {
	patterns := parsePatterns(app.Scripts)
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil {
				for _, script := range scripts {
					if pattrn.regex.MatchString(script) {
						version := detectVersion(pattrn, &script)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

// analyzeDNS 分析 DNS 记录尝试匹配
func analyzeDNS(app *application, dns map[string][]string, detectedApplications *detected) {
	patterns := parsePatterns(app.DNS)
	for dnsType, v := range patterns {
		dnsTypeUpperCase := strings.ToUpper(dnsType)
		for _, pattrn := range v {
			if dnsSlice, ok := dns[dnsTypeUpperCase]; ok {
				for _, dns := range dnsSlice {
					if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(dns)) {
						version := detectVersion(pattrn, &dns)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

// analyzeMeta 分析 meta 尝试匹配
func analyzeMeta(app *application, metas map[string][]string, detectedApplications *detected) {
	patterns := parsePatterns(app.Meta)
	for metaName, v := range patterns {
		metaNameLowerCase := strings.ToLower(metaName)
		for _, pattrn := range v {
			if metaSlice, ok := metas[metaNameLowerCase]; ok {
				for _, meta := range metaSlice {
					if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(meta)) {
						version := detectVersion(pattrn, &meta)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

// analyzeCertIssuer 尝试匹配证书颁发者
func analyzeCertIssuer(app *application, certIssuer []string, detectedApplications *detected) {
	for _, issuerString := range certIssuer {
		if strings.Contains(issuerString, app.CertIssuer) {
			addApp(app, detectedApplications, "", 100)
		}
	}
}

// resolveExcludes 删除需要排除的产品
func resolveExcludes(detected *map[string]*resultApp, value interface{}) {
	patterns := parsePatterns(value)
	for _, v := range patterns {
		for _, excluded := range v {
			delete(*detected, excluded.str)
		}
	}
}

// resolveImplies 如果指纹中存在implies，表示识别出当前产品后有极大可能有关联的产品，例如检测到一个网站使用了 jQuery JavaScript 库，然后在 jQuery 对应的指纹对象中的 "implies" 属性中包含了 "JavaScript"，那么我们可以推断该网站也使用了 JavaScript 技术。
func resolveImplies(apps *map[string]*application, detected *map[string]*resultApp, value interface{}) {
	patterns := parsePatterns(value)
	for _, v := range patterns {
		for _, implied := range v {
			app, ok := (*apps)[implied.str]
			if _, ok2 := (*detected)[implied.str]; ok && !ok2 {
				resApp := &resultApp{Technology{app.Slug, app.Name, implied.confidence, implied.version, app.Icon, app.Website, app.CPE, app.Categories}, app.Excludes, app.Implies}
				(*detected)[implied.str] = resApp
				if app.Implies != nil {
					resolveImplies(apps, detected, app.Implies)
				}
			}
		}
	}
}

// analyzePage 解析页面
func analyzePage(paramURL string, wapp *Wappalyzer, detectedApplications *detected) (links *map[string]struct{}, scrapedData *scraper.ScrapedData, err error) {
	defer func() {
		if err := recover(); err != nil {
			logger.Warn(fmt.Sprintf("%s 捕获到错误: %s", paramURL, err))
			return
		}
	}()

	//检测 URL 是否有效
	if !validateURL(paramURL) {
		//logger.Warn(fmt.Sprintf("无效的 URL : %s", paramURL))
		return nil, nil, errors.New("无效的 URL")
	}
	// 请求 URL 并根据响应获取相关数据
	scraped, page, err := wapp.Scraper.Scrape(paramURL)
	if err != nil {
		//logger.Warn(fmt.Sprintf("%s 爬取失败", paramURL))
		return nil, nil, err
	}

	// 是否进行 JS 渲染页面
	canRenderPage := wapp.Scraper.CanRenderPage()
	reader := strings.NewReader(scraped.HTML)
	doc, err := goquery.NewDocumentFromReader(reader)
	if err == nil {
		//获取可跳转连接
		links = getLinksSlice(doc, paramURL)
	}

	//允许重定向 scraped.URLs.URL为请求后返回的 URL，paramURL 为目标 URL
	if scraped.URL != paramURL {
		(*links)[strings.TrimRight(scraped.URL, "/")] = struct{}{}
		scraped.URL = paramURL
	}

	var wg sync.WaitGroup

	//循环匹配全部 APPS
	for _, app := range wapp.Apps {
		wg.Add(1)
		go func(app *application) {
			defer wg.Done()
			analyzeURL(app, paramURL, detectedApplications)
			if canRenderPage && app.Js != nil {
				analyzeJS(page, app, wapp.Scraper, detectedApplications)
			}
			if canRenderPage && app.Dom != nil {
				analyzeDom(app, doc, detectedApplications)
			}
			if app.HTML != nil {
				analyzeHTML(app, scraped.HTML, detectedApplications)
			}
			if len(scraped.Headers) > 0 && app.Headers != nil {
				analyzeHeaders(app, scraped.Headers, detectedApplications)
			}
			if len(scraped.Cookies) > 0 && app.Cookies != nil {
				analyzeCookies(app, scraped.Cookies, detectedApplications)
			}
			if len(scraped.Scripts) > 0 && app.Scripts != nil {
				analyzeScripts(app, scraped.Scripts, detectedApplications)
			}
			if len(scraped.Meta) > 0 && app.Meta != nil {
				analyzeMeta(app, scraped.Meta, detectedApplications)
			}
			if len(scraped.DNS) > 0 && app.DNS != nil {
				analyzeDNS(app, scraped.DNS, detectedApplications)
			}
			if len(scraped.CertIssuer) > 0 && app.CertIssuer != "" {
				analyzeCertIssuer(app, scraped.CertIssuer, detectedApplications)
			}
		}(app)
	}

	wg.Wait()

	//根据识别出的产品来进行下一步  排除和关联  的操作
	for _, app := range detectedApplications.Apps {
		if app.excludes != nil {
			resolveExcludes(&detectedApplications.Apps, app.excludes)
		}
		if app.implies != nil {
			resolveImplies(&wapp.Apps, &detectedApplications.Apps, app.implies)
		}
	}

	if v, ok := wapp.Scraper.(*scraper.RodScraper); ok {
		v.PutPage(page)
	}

	return links, scraped, nil
}

// analyzePages 解析页面
func analyzePages(paramURLs map[string]struct{}, wapp *Wappalyzer, wappalyzerResult *[]WappFingerResult) (detectedLinks map[string]struct{}, visitedURLs map[string]scraper.ScrapedData, err error) {
	visitedURLs = make(map[string]scraper.ScrapedData)
	detectedLinks = make(map[string]struct{})
	err = errors.New("解析页面失败")

	for paramURL := range paramURLs {
		fingerResult := WappFingerResult{}
		detectedApplications := &detected{Mu: new(sync.Mutex), Apps: make(map[string]*resultApp)}
		//收集可跳转链接，当前链接的请求情况，请求异常信息
		links, scrapedData, retErr := analyzePage(paramURL, wapp, detectedApplications)
		if retErr == nil && scrapedData != nil {
			err = nil
			fingerResult.ResponseData = *scrapedData
			for _, app := range detectedApplications.Apps {
				fingerResult.Technologies = append(fingerResult.Technologies, app.technology)
			}

			*wappalyzerResult = append(*wappalyzerResult, fingerResult)

			if scrapedData != nil {
				visitedURLs[paramURL] = *scrapedData
				if links != nil {
					for link := range *links {
						if _, exists := detectedLinks[link]; !exists {
							detectedLinks[link] = struct{}{}
						}
					}
				}
			}
			wapp.Config.visitedLinks = wapp.Config.visitedLinks + 1
			if wapp.Config.visitedLinks >= wapp.Config.MaxVisitedLinks {
				//logger.Warn(fmt.Sprintf("超出最大可请求链接: %d", wapp.Config.MaxVisitedLinks))
				break
			}

			time.Sleep(time.Duration(wapp.Config.MsDelayBetweenRequests) * time.Millisecond)
		} else {
			visitedURLs[paramURL] = scraper.ScrapedData{}
		}
	}

	return detectedLinks, visitedURLs, err
}

// Analyze 解析 URL
func (wapp *Wappalyzer) Analyze(paramURL string) (wappalyzerResult []WappFingerResult, err error) {
	toVisitURLs := make(map[string]struct{})
	globalVisitedURLs := make(map[string]scraper.ScrapedData)

	//默认异常
	err = errors.New("解析页面失败")

	//避免在处理 URL 时出现不必要地重复斜杠
	paramURL = strings.TrimRight(paramURL, "/")
	toVisitURLs[paramURL] = struct{}{}

	//根据递归深度去进行爬取，每次请求目标 URL，进行指纹识别，然后从页面中提取和目标 URL 同域的链接作为递归目标，并且在全局维护一个公共的已请求链接列表，保证不会重复请求
	for depth := 0; depth <= wapp.Config.MaxDepth; depth++ {
		wapp.Scraper.SetDepth(depth)
		//检测到的链接，已经请求的链接
		links, visitedURLs, retErr := analyzePages(toVisitURLs, wapp, &wappalyzerResult)
		if retErr == nil {
			err = nil
		}
		//更新全局已经请求的链接及其返回数据
		for visitedURL, result := range visitedURLs {
			globalVisitedURLs[visitedURL] = result
		}
		if depth < wapp.Config.MaxDepth {
			toVisitURLs = make(map[string]struct{})
			for link := range links {
				//更新需要继续请求的链接列表，如果全局已请求链接列表中没有数据则可以继续请求
				if _, exists := globalVisitedURLs[link]; !exists {
					toVisitURLs[link] = struct{}{}
				}
			}
		}
	}

	return wappalyzerResult, err
}
