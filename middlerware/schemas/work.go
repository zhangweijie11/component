package schemas

type FingerprintParams struct {
	Urls      []string `json:"urls" binding:"required"`
	Scraper   string   `json:"scraper" binding:"required"`
	MaxDepth  int      `json:"max_depth"`
	UserAgent string   `json:"user_agent"`
}
