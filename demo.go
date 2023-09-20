package main

import (
	"context"
	"fmt"
	wapp "gitlab.example.com/zhangweijie/component/services/fingerprint/wappalyzer"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"sync"
	"time"
)

type Worker struct {
	ID         int // 任务执行者 ID
	Ctx        context.Context
	Wg         *sync.WaitGroup
	TaskChan   chan Task   // 子任务通道
	ResultChan chan string // 子任务结果通道
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
func NewWorker(ctx context.Context, wg *sync.WaitGroup, id int, taskChan chan Task, resultChan chan string) *Worker {
	return &Worker{
		ID:         id,
		Ctx:        ctx,
		Wg:         wg,
		TaskChan:   taskChan,
		ResultChan: resultChan,
	}
}

type FingerprintParams struct {
	Urls      []string `json:"url"`
	Scraper   string   `json:"scraper"`
	MaxDepth  int      `json:"max_depth"`
	UserAgent string   `json:"user_agent"`
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
				fmt.Println("------------>", "子任务取消")
				return
			default:
				fmt.Println("------------>", task)
				time.Sleep(10 * time.Second)
				select {
				case <-w.Ctx.Done():
					fmt.Println("------------>", "任务取消了了了")
					return
				default:
					w.ResultChan <- task.TargetUrl
				}

			}

		}
	}()
}

func FingerprintMainWorker(ctx context.Context, work *toolModels.Work, validParams *FingerprintParams) error {
	quit := make(chan struct{})
	go func() {
		defer close(quit)
		taskChan := make(chan Task, len(validParams.Urls))
		resultChan := make(chan string, len(validParams.Urls))
		var wg sync.WaitGroup
		// 创建并启动多个工作者
		for i := 0; i < 2; i++ {
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
			fmt.Println("------------>", fingerprintResult)
		}

		defer func() {
			if collyWorker != nil {
				collyWorker.Scraper.Close()
			}
			if rodWorker != nil {
				rodWorker.Scraper.Close()
			}
		}()
	}()
	select {
	case <-ctx.Done():
		fmt.Println("------------>", "任务取消")
		return nil
	case <-quit:
		fmt.Println("------------>", "任务完成")
		return nil
	}
}

func run(ctx context.Context) {
	work := &toolModels.Work{
		ID:   1,
		UUID: "11111111",
	}
	validParams := &FingerprintParams{
		Urls:      []string{"aaa", "bbb", "ccc", "ddd"},
		Scraper:   "colly",
		MaxDepth:  0,
		UserAgent: "",
	}

	err := FingerprintMainWorker(ctx, work, validParams)
	if err != nil {
		fmt.Println("------------>", err)
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	go run(ctx)
	time.Sleep(8 * time.Second)
	cancel()
	fmt.Println("------------>", "开始等待")
	time.Sleep(8 * time.Second)

}
