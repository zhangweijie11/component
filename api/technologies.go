package api

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"gitlab.example.com/zhangweijie/component/models"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/templates"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

// TechnologiesCreateApi 入库指纹数据
func TechnologiesCreateApi(c *gin.Context) {
	technologiesFilePath := filepath.Join(global.Config.Server.RootDir, "data/technologies")
	// 读取文件夹中的所有文件
	fileInfos, _ := os.ReadDir(technologiesFilePath)

	// 遍历每个文件
	for _, fileInfo := range fileInfos {
		// 检查文件是否是YAML文件
		if strings.HasSuffix(fileInfo.Name(), ".yaml") {
			// 构建完整的文件路径
			filePath := filepath.Join(technologiesFilePath, fileInfo.Name())

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
					jsonInfo, err := json.Marshal(validTemplate.Info)
					if err != nil {
						logger.Warn("Info 参数序列化出错")
					}
					jsonMatchers, err := json.Marshal(requestData.Matchers)
					if err != nil {
						logger.Warn("Matchers 参数序列化出错")
					}
					for _, pathData := range requestData.Path {
						technology := &models.Technologies{
							Name:              validTemplate.ID,
							Version:           validTemplate.Info.Version,
							Categories:        validTemplate.Info.Categories.String(),
							Tags:              validTemplate.Info.Tags.String(),
							Info:              jsonInfo,
							Method:            requestData.Method.String(),
							Path:              pathData,
							MatchersCondition: requestData.MatchersCondition,
							Matchers:          jsonMatchers,
						}

						err = models.CreateTechnology(technology)

						if err != nil {
							logger.Error("数据库出现错误", err)
						}
					}
				}
			}
		}
	}

	schemas.SuccessCreate(c, "SUCCESS")
	return
}
