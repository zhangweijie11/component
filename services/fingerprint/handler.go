package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal"
	fingResult "gitlab.example.com/zhangweijie/component/services/fingerprint/result"
	wapp "gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer"
	serviceFinger "gitlab.example.com/zhangweijie/portscan/services/service_recognize/fingerprint"
	serviceResult "gitlab.example.com/zhangweijie/portscan/services/service_recognize/result"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/global/utils"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"strings"
	"sync"
	"time"
)

type Worker struct {
	ID         int // 任务执行者 ID
	Ctx        context.Context
	Wg         *sync.WaitGroup
	TaskChan   chan Task                      // 子任务通道
	ResultChan chan []fingResult.FingerResult // 子任务结果通道
}

type Task struct {
	WorkUUID     string // 总任务 ID
	TaskUUID     string // 子任务 ID
	TargetUrl    string // 子任务目标网站
	Scraper      string // 使用的 scraper
	CollyScraper *wapp.Wappalyzer
	RodScraper   *wapp.Wappalyzer
	MaxDepth     int
	UserAgent    string
}

// NewWorker 初始化 worker
func NewWorker(ctx context.Context, wg *sync.WaitGroup, id int, taskChan chan Task, resultChan chan []fingResult.FingerResult) *Worker {
	return &Worker{
		ID:         id,
		Ctx:        ctx,
		Wg:         wg,
		TaskChan:   taskChan,
		ResultChan: resultChan,
	}
}

type FingerprintParams struct {
	Urls      []string `json:"urls"`
	Scraper   string   `json:"scraper"`
	MaxDepth  int      `json:"max_depth"`
	UserAgent string   `json:"user_agent"`
}

// wappalyzerRun 运行 wappalyzer 插件
func wappalyzerRun(url string, collyWorker, rodWorker *wapp.Wappalyzer) (*[]wapp.WappFingerResult, error) {
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
				"wappalyzerResult": &[]wapp.WappFingerResult{},
				"resErr":           nil,
			}
		}

	}()

	select {
	case resMap := <-resCh:
		if resMap["resErr"] == nil {
			return resMap["wappalyzerResult"].(*[]wapp.WappFingerResult), nil
		} else {
			return resMap["wappalyzerResult"].(*[]wapp.WappFingerResult), resMap["resErr"].(error)
		}
	case <-time.After(60 * time.Second):
		return &[]wapp.WappFingerResult{}, errors.New(fmt.Sprintf("%s fingerprint timeout", url))
	}
}

// formatWappalyzerResult 格式化 wappalyzer 插件的结果
func formatWappalyzerResult(allFingerResults *[]fingResult.FingerResult, wappalyzerResult *[]wapp.WappFingerResult) {
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

		fingerResult := fingResult.FingerResult{
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
					if cate, exists := wapp.CategoryMap[category.Name]; exists && item == cate {
						found = true
						break
					}
				}
				if !found {
					categories = append(categories, wapp.CategoryMap[category.Name])
					simpleTechnology := fingResult.SimpleTechnology{
						Name:    technology.Name,
						Version: technology.Version,
					}
					// 对产品组件进行自定义分类
					switch wapp.CategoryMap[category.Name] {
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

			fingerResult.Technologies = append(fingerResult.Technologies, fingResult.Technology{
				Name:       technology.Name,
				Version:    technology.Version,
				Categories: categories,
			})

		}

		*allFingerResults = append(*allFingerResults, fingerResult)
	}
}

// getWapplyzerWorker 获取可用插件
func getWapplyzerWorker(scraper string, maxDepth int, userAgent string) (wapplyzer *wapp.Wappalyzer, err error) {
	wappalyzer, err := wapp.NewWappalyzer(maxDepth, userAgent)
	if err != nil {
		logger.Error("初始化 Wappalyzer 插件出现错误", err)
		return nil, err
	} else {
		err = wapp.NewWappalyzerScraper(wappalyzer, scraper)
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
				var fingerResults []fingResult.FingerResult

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
							tmpResult.Technologies = append(tmpResult.Technologies, wapp.Technology{Name: vResult.Name, Categories: vResult.Categories})
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

func FingerprintMainWorker(ctx context.Context, work *toolModels.Work, validParams *FingerprintParams) error {
	quit := make(chan struct{})
	go func() {
		defer close(quit)
		onePercent := float64(100 / len(validParams.Urls))
		taskChan := make(chan Task, len(validParams.Urls))
		resultChan := make(chan []fingResult.FingerResult, len(validParams.Urls))
		var wg sync.WaitGroup
		// 创建并启动多个工作者
		for i := 0; i < global.Config.Server.Worker; i++ {
			worker := NewWorker(ctx, &wg, i, taskChan, resultChan)
			worker.GroupFingerprintWorker()
			wg.Add(1)
		}
		var collyWorker *wapp.Wappalyzer
		var rodWorker *wapp.Wappalyzer
		if validParams.Scraper == "colly" {
			collyWorker, _ = getWapplyzerWorker("colly", validParams.MaxDepth, validParams.UserAgent)
		} else {
			rodWorker, _ = getWapplyzerWorker("rod", validParams.MaxDepth, validParams.UserAgent)
		}

		go func() {
			// 通知消费者所有任务已经推送完毕
			defer close(taskChan)
			for _, url := range validParams.Urls {
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

		var finalResult [][]fingResult.FingerResult

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
		return errors.New(schemas.WorkCancelErr)
	case <-quit:
		return nil
	}
}

// portScanFingerprintWorker 端口扫描过程中使用的指纹识别
func portScanFingerprintWorker(url string, collyWorker, rodWorker *wapp.Wappalyzer) (*[]fingResult.FingerResult, error) {
	var fingerResults []fingResult.FingerResult
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
				tmpResult.Technologies = append(tmpResult.Technologies, wapp.Technology{Name: vResult.Name, Categories: vResult.Categories})
			}
		}
	}

	formatWappalyzerResult(&fingerResults, wappalyzerResult)

	for _, fingerResult := range fingerResults {
		logger.Info(fmt.Sprintf("------------> URL %s -------> Title %s -------> Technologies %s", fingerResult.URL, fingerResult.Title, fingerResult.Technologies))
	}

	return &fingerResults, nil
}

// 合并服务识别和指纹识别结果中的产品组件
func mergeTechnology(fingerprintTechnologies []fingResult.Technology, serviceTechnologies []serviceFinger.Technology) []fingResult.Technology {
	tmpData1 := make(map[string]struct{})
	tmpData2 := make(map[string]fingResult.Technology)
	for _, technology := range fingerprintTechnologies {
		if _, ok := tmpData1[strings.ToLower(technology.Name)]; !ok {
			tmpData1[strings.ToLower(technology.Name)] = struct{}{}
			tmpData2[technology.Name] = technology
		}
	}
	for _, technology := range serviceTechnologies {
		if _, ok := tmpData1[strings.ToLower(technology.Name)]; !ok {
			tmpData1[strings.ToLower(technology.Name)] = struct{}{}
			newTechnology := fingResult.Technology{
				Name:       technology.Name,
				Version:    technology.Version,
				Categories: technology.Categories,
			}
			tmpData2[technology.Name] = newTechnology
		}
	}
	var mergeResult []fingResult.Technology
	for _, technology := range tmpData2 {
		mergeResult = append(mergeResult, technology)
	}

	return mergeResult
}

func GetPortScanFingerprint(serviceRecognizeScanResults map[string]map[int]*serviceResult.Response) map[string]map[int]*fingResult.FingerResult {
	targetUrls := make(map[string]*serviceResult.Response)
	// 提取有效的 URL 数据
	for _, serviceRecognizeScanResult := range serviceRecognizeScanResults {
		for _, response := range serviceRecognizeScanResult {
			if response.Protocol == "http" || response.Protocol == "https" {
				url := fmt.Sprintf("%s://%s:%d", response.Protocol, response.IP, response.Port)
				targetUrls[url] = response
			}
		}
	}

	finalResult := make(map[string]map[int]*fingResult.FingerResult)

	if len(targetUrls) > 0 {
		collyWorker, _ := getWapplyzerWorker("colly", 0, "")
		rodWorker, _ := getWapplyzerWorker("rod", 0, "")
		defer collyWorker.Scraper.Close()
		defer rodWorker.Scraper.Close()
		for targetUrl, sResult := range targetUrls {
			tmpResult, err := portScanFingerprintWorker(targetUrl, collyWorker, rodWorker)
			if err == nil && len(*tmpResult) > 0 {
				mergeTechnologyResult := mergeTechnology((*tmpResult)[0].Technologies, sResult.Fingerprint.Technologies)
				(*tmpResult)[0].Technologies = mergeTechnologyResult
				finalResult[sResult.IP] = map[int]*fingResult.FingerResult{
					sResult.Port: &(*tmpResult)[0],
				}
			}
		}
	}

	return finalResult
}
