package schemas

// FingerprintTaskCreateSchema 指纹识别任务参数
type FingerprintTaskCreateSchema struct {
	URL       []string `json:"url" binding:"required"`
	Scraper   string   `json:"scraper" binding:"oneof='' rod colly"` // 使用那种爬取框架，针对 wappalyzer 插件，有 rod 和 colly 两个选择，默认为 rod
	MaxDepth  int      `json:"max_depth" binding:"gte=0,lte=3"`      // 最大递归深度
	UserAgent string   `json:"user_agent"`                           // 自定义 UA
}

// CertificateTaskCreateSchema 证书任务参数
type CertificateTaskCreateSchema struct {
	Url string `json:"url" binding:"required"`
}
