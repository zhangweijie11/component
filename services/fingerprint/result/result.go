package result

type SimpleTechnology struct {
	Name    string `json:"name"`    // 名称
	Version string `json:"version"` // 版本
}

type Technology struct {
	Name       string   `json:"name"`       // 名称
	Version    string   `json:"version"`    // 版本
	Categories []string `json:"categories"` // 类别列表
}

type FingerResult struct {
	URL                 string             `json:"url"`                  // URL
	StatusCode          int                `json:"status_code"`          // 响应状态码
	Title               string             `json:"title"`                // 网页标题
	Headers             map[string]string  `json:"headers"`              // 响应头
	HTML                string             `json:"html"`                 // 网站正文内容
	Technologies        []Technology       `json:"technologies"`         // 产品组件
	Framework           []SimpleTechnology `json:"framework"`            // 框架
	Product             []SimpleTechnology `json:"product"`              // 产品
	Component           []SimpleTechnology `json:"component"`            // 组件
	WebContainer        []SimpleTechnology `json:"web_container"`        // Web 容器
	WebFramework        []SimpleTechnology `json:"web_framework"`        // Web 前端框架
	ProgrammingLanguage []SimpleTechnology `json:"programming_language"` // 开发语言
	Favicon             string             `json:"favicon"`              // 图标
	FaviconHash         string             `json:"favicon_hash"`         // 图标hash 值
	Certificate         string             `json:"certificate"`          // 证书数据
}
