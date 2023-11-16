package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"gitlab.example.com/zhangweijie/component/middlerware/schemas"
	"gitlab.example.com/zhangweijie/component/models"
	"gitlab.example.com/zhangweijie/component/routers"
	"gitlab.example.com/zhangweijie/component/services/fingerprint"
	tool "gitlab.example.com/zhangweijie/tool-sdk/cmd"
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	toolSchemas "gitlab.example.com/zhangweijie/tool-sdk/middleware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"gitlab.example.com/zhangweijie/tool-sdk/option"
	toolRouters "gitlab.example.com/zhangweijie/tool-sdk/routers"
)

type executorIns struct {
	global.ExecutorIns
}

func (ei *executorIns) ValidWorkCreateParams(params map[string]interface{}) (err error) {
	var schema = new(schemas.FingerprintTaskCreateSchema)
	if err = toolSchemas.CustomBindSchema(params, schema, schemas.RegisterValidatorRule); err == nil || err.Error() == "" {
		err = toolSchemas.ValidateLength(schema.URL, 0, 100)
	}

	return err
}

func (ei *executorIns) ExecutorMainFunc(ctx context.Context, params map[string]interface{}) error {
	errChan := make(chan error)
	go func() {
		work := params["work"].(*toolModels.Work)
		var validParams schemas.FingerprintTaskCreateSchema
		err := json.Unmarshal(work.Params, &validParams)
		if err != nil {
			logger.Error(toolSchemas.JsonParseErr, err)
			errChan <- err
		} else {
			err = fingerprint.FingerprintMainWorker(ctx, work, &validParams)
			errChan <- err
		}
	}()
	select {
	case <-ctx.Done():
		return errors.New(toolSchemas.WorkCancelErr)
	case err := <-errChan:
		return err
	}
}

func main() {
	defaultOption := option.GetDefaultOption()
	defaultOption.ExecutorIns = &executorIns{}
	defaultOption.ValidModels = []interface{}{&toolModels.Work{}, &toolModels.Task{}, &toolModels.Result{}, &models.Technologies{}}
	defaultOption.ValidRouters = []func(*gin.Engine) gin.IRoutes{toolRouters.InitPingRouter, toolRouters.InitWorkRouter, routers.InitTechnologiesRouter}
	tool.Start(defaultOption)
}
