package schemas

var taskValidatorErrorMessage = map[string]string{
	"Urlsrequired":    "缺少任务目标",
	"Scraperrequired": "缺少任务模型",
}

// RegisterValidatorRule 注册参数验证错误消息, Key = e.StructNamespace(), value.key = e.Field()+e.Tag()
var RegisterValidatorRule = map[string]map[string]string{
	"FingerprintTaskCreateSchema": taskValidatorErrorMessage,
	"CertificateTaskCreateSchema": taskValidatorErrorMessage,
}
