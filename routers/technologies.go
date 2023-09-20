package routers

import (
	"gitlab.example.com/zhangweijie/component/api"

	"github.com/gin-gonic/gin"
)

func InitTechnologiesRouter(engine *gin.Engine) gin.IRoutes {
	var group = engine.Group("/technologies")
	{
		group.GET("", api.TechnologiesCreateApi)
	}
	return group
}
