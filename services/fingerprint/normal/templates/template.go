package templates

// Template 模板是一个 YAML 输入文件，用于定义模板的所有请求和其他元数据。
type Template struct {
	// description: |
	//   ID 是模版唯一标识，ID 不得包含空格。
	// examples:
	//   id: git-config
	ID string `yaml:"id" json:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	// description: |
	//   信息包含有关模板的元数据信息。信息块提供名称、作者、严重性、描述、参考、标签和 metadata 。它还包含严重性字段，指示模板的严重性，信息块还支持动态字段，因此可以定义 N 个 key: value 块来提供有关模板的更多有用信息。
	//  Reference 是另一个流行的标签，用于定义模板的外部参考链接。另一个始终添加到 info 块中的有用标签是标签。这允许您根据 cve 、 rce 等目的为模板设置一些自定义标签。这允许 nuclei 使用您的输入标签识别模板并仅运行它们。
	// examples:
	// info:
	//   name: Git Config File Detection Template
	//   author: Ice3man
	//   severity: medium
	//   description: Searches for the pattern /.git/config on passed URLs.
	//   reference: https://www.acunetix.com/vulnerabilities/web/git-repository-found/
	//   tags: git,config
	Info *Info `yaml:"info" json:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template"`
	// description: |
	//   Requests contains the http request to make in the template.
	// examples:
	//   - value: exampleNormalHTTPRequest
	RequestsWithHTTP []*Request `yaml:"http,omitempty" json:"http,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
}
