package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.example.com/zhangweijie/component/middlerware/schemas"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/result"
	gowap "gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer"
	portServiceFinger "gitlab.example.com/zhangweijie/portscan/services/service_recognize/fingerprint"
	portServiceResult "gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/global/utils"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	toolSchemas "gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"strings"
	"sync"
	"time"
)

type Worker struct {
	ID         int // 任务执行者 ID
	Ctx        context.Context
	Wg         *sync.WaitGroup
	TaskChan   chan Task                  // 子任务通道
	ResultChan chan []result.FingerResult // 子任务结果通道
}

type Task struct {
	WorkUUID     string // 总任务 ID
	TaskUUID     string // 子任务 ID
	TargetUrl    string // 子任务目标网站
	Scraper      string // 使用的 scraper
	CollyScraper *gowap.Wappalyzer
	RodScraper   *gowap.Wappalyzer
	MaxDepth     int
	UserAgent    string
}

// NewWorker 初始化 worker
func NewWorker(ctx context.Context, wg *sync.WaitGroup, id int, taskChan chan Task, resultChan chan []result.FingerResult) *Worker {
	return &Worker{
		ID:         id,
		Ctx:        ctx,
		Wg:         wg,
		TaskChan:   taskChan,
		ResultChan: resultChan,
	}
}

// wappalyzerRun 运行 wappalyzer 插件
func wappalyzerRun(url string, collyWorker, rodWorker *gowap.Wappalyzer) (*[]gowap.WappFingerResult, error) {
	resCh := make(chan map[string]interface{})

	go func() {
		if collyWorker != nil {
			wappalyzerResult, err := collyWorker.Analyze(url)
			if (err != nil || len(wappalyzerResult) == 0) && rodWorker != nil {
				wappalyzerResult, err = rodWorker.Analyze(url)

				resCh <- map[string]interface{}{
					"wappalyzerResult": &wappalyzerResult,
					"resErr":           err,
				}
			} else {
				resCh <- map[string]interface{}{
					"wappalyzerResult": &wappalyzerResult,
					"resErr":           err,
				}
			}
		} else if rodWorker != nil {
			wappalyzerResult, err := rodWorker.Analyze(url)

			resCh <- map[string]interface{}{
				"wappalyzerResult": &wappalyzerResult,
				"resErr":           err,
			}
		} else {
			resCh <- map[string]interface{}{
				"wappalyzerResult": &[]gowap.WappFingerResult{},
				"resErr":           nil,
			}
		}

	}()

	select {
	case resMap := <-resCh:
		if resMap["resErr"] == nil {
			return resMap["wappalyzerResult"].(*[]gowap.WappFingerResult), nil
		} else {
			return resMap["wappalyzerResult"].(*[]gowap.WappFingerResult), resMap["resErr"].(error)
		}
	case <-time.After(60 * time.Second):
		return &[]gowap.WappFingerResult{}, errors.New(fmt.Sprintf("%s fingerprint timeout", url))
	}
}

// formatWappalyzerResult 格式化 wappalyzer 插件的结果
func formatWappalyzerResult(allFingerResults *[]result.FingerResult, wappalyzerResult *[]gowap.WappFingerResult) {
	// 处理全部目标 URL 的结果数据
	for _, value := range *wappalyzerResult {
		// 重新设置响应头
		newHeaders := make(map[string]string)
		for k, v := range value.ResponseData.Headers {
			newHeaders[k] = strings.Join(v, ",")
		}

		certInfo, err := json.Marshal(value.ResponseData.Certificate)
		if err != nil {
			certInfo = []byte{}
		}

		fingerResult := result.FingerResult{
			URL:         value.ResponseData.URL,
			StatusCode:  value.ResponseData.StatusCode,
			Title:       value.ResponseData.Title,
			Headers:     newHeaders,
			HTML:        value.ResponseData.HTML,
			Favicon:     value.ResponseData.Favicon,
			FaviconHash: value.ResponseData.FaviconHash,
			Certificate: string(certInfo),
		}

		// 处理单个 URL 结果数据中的产品组件数据
		for _, technology := range value.Technologies {
			categories := make([]string, 0)
			for _, category := range technology.Categories {
				found := false
				// 遍历列表，查找元素
				for _, item := range categories {
					if cate, exists := gowap.CategoryMap[category.Name]; exists && item == cate {
						found = true
						break
					}
				}
				if !found {
					categories = append(categories, gowap.CategoryMap[category.Name])
					simpleTechnology := result.SimpleTechnology{
						Name:    technology.Name,
						Version: technology.Version,
					}
					// 对产品组件进行自定义分类
					switch gowap.CategoryMap[category.Name] {
					case "product":
						fingerResult.Product = append(fingerResult.Product, simpleTechnology)
					case "webFramework":
						fingerResult.WebFramework = append(fingerResult.WebFramework, simpleTechnology)
					case "webContainer":
						fingerResult.WebContainer = append(fingerResult.WebContainer, simpleTechnology)
					case "programmingLanguage":
						fingerResult.ProgrammingLanguage = append(fingerResult.ProgrammingLanguage, simpleTechnology)
					case "framework":
						fingerResult.Framework = append(fingerResult.Framework, simpleTechnology)
					case "component":
						fingerResult.Component = append(fingerResult.Component, simpleTechnology)
					}
				}
			}

			fingerResult.Technologies = append(fingerResult.Technologies, result.Technology{
				Name:       technology.Name,
				Version:    technology.Version,
				Categories: categories,
			})

		}

		*allFingerResults = append(*allFingerResults, fingerResult)
	}
}

// getWapplyzerWorker 获取可用插件
func getWapplyzerWorker(scraper string, maxDepth int, userAgent string) (wapplyzer *gowap.Wappalyzer, err error) {
	wappalyzer, err := gowap.NewWappalyzer(maxDepth, userAgent)
	if err != nil {
		logger.Error("初始化 Wappalyzer 插件出现错误", err)
		return nil, err
	} else {
		err = gowap.NewWappalyzerScraper(wappalyzer, scraper)
		if err != nil {
			return nil, err
		} else {
			return wappalyzer, nil
		}
	}
}

// GroupFingerprintWorker 指纹识别方法
func (w *Worker) GroupFingerprintWorker() {
	go func() {
		defer w.Wg.Done()
		for task := range w.TaskChan {
			select {
			case <-w.Ctx.Done():
				return
			default:
				var fingerResults []result.FingerResult

				// 获取 wappalyzer 插件结果
				wappalyzerResult, _ := wappalyzerRun(task.TargetUrl, task.CollyScraper, task.RodScraper)

				for _, tmpResult := range *wappalyzerResult {
					normalResult, _ := normal.NormalFingerScan(&tmpResult.ResponseData)
					// 结果去重
					var tmpTechnologies []string
					for _, technology := range tmpResult.Technologies {
						tmpTechnologies = append(tmpTechnologies, strings.ToLower(technology.Name))
					}
					for _, vResult := range normalResult {
						if !utils.JudgeDuplication(strings.ToLower(vResult.Name), tmpTechnologies) {
							tmpResult.Technologies = append(tmpResult.Technologies, gowap.Technology{Name: vResult.Name, Categories: vResult.Categories})
						}
					}
				}

				formatWappalyzerResult(&fingerResults, wappalyzerResult)

				for _, fingerResult := range fingerResults {
					logger.Info(fmt.Sprintf("------------> URL %s -------> Title %s -------> Technologies %s", fingerResult.URL, fingerResult.Title, fingerResult.Technologies))
				}
				select {
				case <-w.Ctx.Done():
					return
				default:
					w.ResultChan <- fingerResults
				}
			}
		}
	}()
}

func FingerprintMainWorker(ctx context.Context, work *toolModels.Work, validParams *schemas.FingerprintTaskCreateSchema) error {
	quit := make(chan struct{})
	go func() {
		defer close(quit)
		onePercent := float64(100 / len(validParams.URL))
		taskChan := make(chan Task, len(validParams.URL))
		resultChan := make(chan []result.FingerResult, len(validParams.URL))
		var wg sync.WaitGroup
		// 创建并启动多个工作者
		for i := 0; i < global.Config.Server.Worker; i++ {
			worker := NewWorker(ctx, &wg, i, taskChan, resultChan)
			worker.GroupFingerprintWorker()
			wg.Add(1)
		}
		var collyWorker *gowap.Wappalyzer
		var rodWorker *gowap.Wappalyzer
		if validParams.Scraper == "colly" {
			collyWorker, _ = getWapplyzerWorker("colly", validParams.MaxDepth, validParams.UserAgent)
		} else {
			rodWorker, _ = getWapplyzerWorker("rod", validParams.MaxDepth, validParams.UserAgent)
		}

		go func() {
			// 通知消费者所有任务已经推送完毕
			defer close(taskChan)
			for _, url := range validParams.URL {
				task := Task{
					WorkUUID:     work.UUID, // 总任务 ID
					TargetUrl:    url,       // 子任务目标网站
					Scraper:      validParams.Scraper,
					CollyScraper: collyWorker,
					RodScraper:   rodWorker,
					MaxDepth:     validParams.MaxDepth,
					UserAgent:    validParams.UserAgent,
				}
				taskChan <- task
			}
		}()

		go func() {
			wg.Wait()
			// 通知消费者所有任务结果已经推送完毕
			close(resultChan)

		}()

		var finalResult [][]result.FingerResult

		for fingerprintResult := range resultChan {
			if work.ProgressType != "" && work.ProgressUrl != "" {
				pushProgress := &global.Progress{WorkUUID: work.UUID, ProgressType: work.ProgressType, ProgressUrl: work.ProgressUrl, Progress: 0}
				pushProgress.Progress += onePercent
				// 回传进度
				global.ValidProgressChan <- pushProgress
			}
			if len(fingerprintResult) > 0 {
				finalResult = append(finalResult, fingerprintResult)
			}
		}

		defer func() {
			if collyWorker != nil {
				collyWorker.Scraper.Close()
			}
			if rodWorker != nil {
				rodWorker.Scraper.Close()
			}
		}()
		if work.CallbackType != "" && work.CallbackUrl != "" {
			pushResult := &global.Result{WorkUUID: work.UUID, CallbackType: work.CallbackType, CallbackUrl: work.CallbackUrl, Result: map[string]interface{}{"result": finalResult}}
			// 回传结果
			global.ValidResultChan <- pushResult
		}

	}()

	select {
	case <-ctx.Done():
		return errors.New(toolSchemas.WorkCancelErr)
	case <-quit:
		return nil
	}
}

// portScanFingerprintWorker 端口扫描过程中使用的指纹识别
func portScanFingerprintWorker(url string, collyWorker, rodWorker *gowap.Wappalyzer) (*[]result.FingerResult, error) {
	var fingerResults []result.FingerResult
	wappalyzerResult, err := wappalyzerRun(url, collyWorker, rodWorker)
	if err != nil {
		return nil, err
	}
	for _, tmpResult := range *wappalyzerResult {
		normalResult, _ := normal.NormalFingerScan(&tmpResult.ResponseData)
		// 结果去重
		var tmpTechnologies []string
		for _, technology := range tmpResult.Technologies {
			tmpTechnologies = append(tmpTechnologies, strings.ToLower(technology.Name))
		}
		for _, vResult := range normalResult {
			if !utils.JudgeDuplication(strings.ToLower(vResult.Name), tmpTechnologies) {
				tmpResult.Technologies = append(tmpResult.Technologies, gowap.Technology{Name: vResult.Name, Categories: vResult.Categories})
			}
		}
	}

	formatWappalyzerResult(&fingerResults, wappalyzerResult)

	return &fingerResults, nil
}

// 合并服务识别和指纹识别结果中的产品组件
func mergeTechnology(fingerprintTechnologies []result.Technology, serviceTechnologies []portServiceFinger.Technology) []result.Technology {
	tmpData1 := make(map[string]struct{})
	tmpData2 := make(map[string]result.Technology)
	for _, technology := range fingerprintTechnologies {
		if _, ok := tmpData1[strings.ToLower(technology.Name)]; !ok {
			tmpData1[strings.ToLower(technology.Name)] = struct{}{}
			tmpData2[technology.Name] = technology
		}
	}
	for _, technology := range serviceTechnologies {
		if _, ok := tmpData1[strings.ToLower(technology.Name)]; !ok {
			tmpData1[strings.ToLower(technology.Name)] = struct{}{}
			newTechnology := result.Technology{
				Name:       technology.Name,
				Version:    technology.Version,
				Categories: technology.Categories,
			}
			tmpData2[technology.Name] = newTechnology
		}
	}
	var mergeResult []result.Technology
	for _, technology := range tmpData2 {
		mergeResult = append(mergeResult, technology)
	}

	return mergeResult
}

func GetPortScanFingerprint(serviceRecognizeResult map[string]map[int]*portServiceResult.RecognizeResponse) map[string]map[int]*result.FingerResult {
	targetUrls := make(map[string]*portServiceResult.RecognizeResponse)
	// 提取有效的 URL 数据
	for _, recognizeResult := range serviceRecognizeResult {
		for _, recognizeResponse := range recognizeResult {
			if recognizeResponse.Protocol == "http" || recognizeResponse.Protocol == "https" {
				url := fmt.Sprintf("%s://%s:%d", recognizeResponse.Protocol, recognizeResponse.IP, recognizeResponse.Port)
				targetUrls[url] = recognizeResponse
			}
		}
	}

	finalResult := make(map[string]map[int]*result.FingerResult)

	if len(targetUrls) > 0 {
		collyWorker, _ := getWapplyzerWorker("colly", 0, "")
		rodWorker, _ := getWapplyzerWorker("rod", 0, "")
		defer collyWorker.Scraper.Close()
		defer rodWorker.Scraper.Close()
		for targetUrl, serviceResult := range targetUrls {
			tmpResult, err := portScanFingerprintWorker(targetUrl, collyWorker, rodWorker)
			if err == nil && len(*tmpResult) > 0 {
				mergeTechnologyResult := mergeTechnology((*tmpResult)[0].Technologies, serviceResult.Fingerprint.Technologies)
				(*tmpResult)[0].Technologies = mergeTechnologyResult
				finalResult[serviceResult.IP] = map[int]*result.FingerResult{
					serviceResult.Port: &(*tmpResult)[0],
				}
			}
		}
	}

	return finalResult
}
