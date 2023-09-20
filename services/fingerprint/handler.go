package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/result"
	wapp "gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/global/utils"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	toolServices "gitlab.example.com/zhangweijie/tool-sdk/services"
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
	CollyScraper *wapp.Wappalyzer
	RodScraper   *wapp.Wappalyzer
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
func formatWappalyzerResult(allFingerResults *[]result.FingerResult, wappalyzerResult *[]wapp.WappFingerResult) {
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
					if cate, exists := wapp.CategoryMap[category.Name]; exists && item == cate {
						found = true
						break
					}
				}
				if !found {
					categories = append(categories, wapp.CategoryMap[category.Name])
					simpleTechnology := result.SimpleTechnology{
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
		pushProgress := &toolServices.Progress{WorkUUID: work.UUID, ProgressType: work.ProgressType, ProgressUrl: work.ProgressUrl, Progress: 0}
		pushResult := &toolServices.Result{WorkUUID: work.UUID, CallbackType: work.CallbackType, CallbackUrl: work.CallbackUrl}
		onePercent := float32(100 / len(validParams.Urls))
		taskChan := make(chan Task, len(validParams.Urls))
		resultChan := make(chan []result.FingerResult, len(validParams.Urls))
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

		for fingerprintResult := range resultChan {
			if work.ProgressType != "" && work.ProgressUrl != "" {
				pushProgress.Progress += onePercent
				pushProgress.PushProgress()
			}
			fmt.Println("------------>", fingerprintResult[0].Technologies)
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
			pushResult.PushResult()
		}

	}()

	select {
	case <-ctx.Done():
		return errors.New(schemas.CancelWorkErr)
	case <-quit:
		return nil
	}

}
