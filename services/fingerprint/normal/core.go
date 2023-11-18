package normal

import (
	"encoding/json"
	"fmt"
	"gitlab.example.com/zhangweijie/component/models"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/matchers"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/templates"
	gowap "gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer/scraper"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ReadFromFilePath 从 URL 或者文件中读取指纹数据
func ReadFromFilePath() ([]*templates.Template, error) {
	var allValidTemplates []*templates.Template
	technologiesPath := filepath.Join(global.Config.Server.RootDir, "data/technologies")
	// 读取文件夹中的所有文件
	fileInfos, _ := os.ReadDir(technologiesPath)

	// 遍历每个文件
	for _, fileInfo := range fileInfos {
		// 检查文件是否是YAML文件
		if strings.HasSuffix(fileInfo.Name(), ".yaml") {
			// 构建完整的文件路径
			filePath := filepath.Join(technologiesPath, fileInfo.Name())

			// 读取文件内容
			content, err := os.ReadFile(filePath)
			if err != nil {
				logger.Warn(fmt.Sprintf("无法读取文件 %s: %v\n", filePath, err))
				continue
			}

			// 解析YAML数据到结构体
			var validTemplate templates.Template
			err = yaml.Unmarshal(content, &validTemplate)
			if err != nil {
				logger.Warn(fmt.Sprintf("无法解析文件 %s: %v\n", filePath, err))
				continue
			} else {
				for _, requestData := range validTemplate.RequestsWithHTTP {
					if requestData.MatchersCondition == "" {
						requestData.MatchersCondition = "or"
					}

					for _, matcher := range requestData.Matchers {
						// 编译各种匹配条件
						err = matcher.CompileMatchers()
						if err != nil {
							logger.Warn("编译匹配器出现问题")
						}
					}
				}
				allValidTemplates = append(allValidTemplates, &validTemplate)
			}
		}
	}

	return allValidTemplates, nil
}

// ReadFromDB 从数据库中读取指纹数据
func ReadFromDB() ([]*templates.Template, error) {
	var allValidTemplates []*templates.Template
	allDBTemplates, err := models.GetAllTechnology()
	if err != nil {
		logger.Error("获取指纹数据出现错误", err)
	}
	for _, dbTemplateData := range *allDBTemplates {
		// 解析YAML数据到结构体
		var validTemplate templates.Template
		var validInfo templates.Info
		var validMatchers []*matchers.Matcher
		var validRequest templates.Request

		err = json.Unmarshal(dbTemplateData.Info, &validInfo)
		err = json.Unmarshal(dbTemplateData.Matchers, &validMatchers)
		httpMethodType, err := templates.ToHTTPMethodTypes(dbTemplateData.Method)
		validRequest.Method = templates.HTTPMethodTypeHolder{MethodType: httpMethodType}
		validRequest.Path = []string{dbTemplateData.Path}
		validRequest.MatchersCondition = dbTemplateData.MatchersCondition
		validRequest.Matchers = validMatchers

		for _, validMatcher := range validRequest.Matchers {
			// 编译各种匹配条件
			err = validMatcher.CompileMatchers()
			if err != nil {
				logger.Warn("编译匹配器出现问题")
			}
		}
		validTemplate.ID = dbTemplateData.Name
		validTemplate.Info = &validInfo
		validTemplate.RequestsWithHTTP = []*templates.Request{&validRequest}
		allValidTemplates = append(allValidTemplates, &validTemplate)
	}
	return allValidTemplates, nil
}

// LoadAllTemplate 加载指纹数据
func LoadAllTemplate() ([]*templates.Template, error) {
	//ValidTemplates, err := ReadFromFilePath()
	ValidTemplates, err := ReadFromDB()
	if err != nil {
		return nil, err
	}

	return ValidTemplates, nil
}

type resultApp struct {
	technology gowap.Technology // 产品
	excludes   interface{}      // 需要排除的产品
	implies    interface{}      // 该产品依赖的产品
}

// 检测到的结果
type detected struct {
	Mu   *sync.Mutex
	Apps map[string]*resultApp
}

// addApp 将检测到的应用程序添加到结果列表， 如果已检测到该应用程序，我们将合并它（版本、置信度等）
func addApp(app *templates.Template, detectedApplications *detected, version string, confidence int) {
	detectedApplications.Mu.Lock()
	if _, ok := (*detectedApplications).Apps[app.ID]; !ok {
		var categories []gowap.ExtendedCategory
		for _, cate := range app.Info.Categories.ToSlice() {
			categories = append(categories, gowap.ExtendedCategory{Name: cate})
		}
		resApp := &resultApp{technology: gowap.Technology{Name: app.ID, Categories: categories}}
		(*detectedApplications).Apps[resApp.technology.Name] = resApp
	} else {
		if (*detectedApplications).Apps[app.ID].technology.Version == "" {
			(*detectedApplications).Apps[app.ID].technology.Version = version
		}
		if confidence > (*detectedApplications).Apps[app.ID].technology.Confidence {
			(*detectedApplications).Apps[app.ID].technology.Confidence = confidence
		}
	}
	detectedApplications.Mu.Unlock()
}

// NormalFingerScan 常规指纹扫描
func NormalFingerScan(sourceResponseData *scraper.ScrapedData) ([]gowap.Technology, error) {
	data := make(map[string]interface{})
	data["url"] = sourceResponseData.URL
	data["status_code"] = sourceResponseData.StatusCode
	data["title"] = sourceResponseData.Title
	data["body"] = sourceResponseData.HTML
	data["headers"] = sourceResponseData.Headers
	data["scripts"] = sourceResponseData.Scripts
	data["cookies"] = sourceResponseData.Cookies
	data["meta"] = sourceResponseData.Meta
	data["cert_issuer"] = sourceResponseData.CertIssuer
	data["dns"] = sourceResponseData.DNS
	data["favicon"] = sourceResponseData.Favicon
	allTemplates, _ := LoadAllTemplate()
	detectedApplications := &detected{Mu: new(sync.Mutex), Apps: make(map[string]*resultApp)}
	var wg sync.WaitGroup
	for _, template := range allTemplates {
		wg.Add(1)
		go func(template *templates.Template) {
			defer wg.Done()
			templateData := make(map[string]interface{})
			templateData["id"] = template.ID
			templateData["categories"] = template.Info.Categories.ToSlice()
			for _, requestData := range template.RequestsWithHTTP {
				var matchersDetectedStatus bool
				var detectedStatuses []bool
				for _, path := range requestData.Path {
					if path == "{{BaseURL}}" {
						for _, matcher := range requestData.Matchers {
							detectedStatus, _ := matcher.Match(data)
							detectedStatuses = append(detectedStatuses, detectedStatus)
						}
					}
				}
				if requestData.MatchersCondition == "and" {
					for _, value := range detectedStatuses {
						if !value {
							matchersDetectedStatus = false
						}
					}
				} else {
					for _, value := range detectedStatuses {
						if value {
							matchersDetectedStatus = true
						}
					}
				}

				if matchersDetectedStatus {
					addApp(template, detectedApplications, template.Info.Version, template.Info.Confidence)
				}

			}
		}(template)
	}

	wg.Wait()

	var technologies []gowap.Technology

	for _, app := range detectedApplications.Apps {
		technologies = append(technologies, app.technology)
	}

	return technologies, nil
}
