package templates

// Info 包含有关模板的元数据信息
type Info struct {
	// description: |
	//   名称应该是标识模板功能的良好简短摘要。
	//
	// examples:
	//   - value: "\"bower.json file disclosure\""
	//   - value: "\"Nagios Default Credentials Check\""
	Name string `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"title=name of the template,description=Name is a short summary of what the template does,example=Nagios Default Credentials Check"`
	// description: |
	//   模板的作者，也可以指定多个值，用逗号分隔
	//
	// examples:
	//   - value: "\"<username>\""
	Authors StringSlice `json:"author,omitempty" yaml:"author,omitempty" jsonschema:"title=author of the template,description=Author is the author of the template,example=username"`
	// description: |
	//   模板的作者，也可以指定多个值，用逗号分隔
	//
	// examples:
	//   - value: "\"<username>\""
	Confidence int    `json:"confidence,omitempty" yaml:"confidence,omitempty" jsonschema:"title=confidence of the template,description=confidence is the confidence of the template"`
	Version    string `json:"version,omitempty" yaml:"version,omitempty" jsonschema:"title=version of the template,description=version is the confidence of the template"`

	// description: |
	//   模板的任何标记,也可以指定多个值，用逗号分隔
	//
	// examples:
	//   - name: Example tags
	//     value: "\"cve,cve2019,grafana,auth-bypass,dos\""
	Tags StringSlice `json:"tags,omitempty" yaml:"tags,omitempty" jsonschema:"title=tags of the template,description=Any tags for the template"`
	// description: |
	//   模板的任何标记,也可以指定多个值，用逗号分隔
	//
	// examples:
	//   - name: Example tags
	//     value: "\"cve,cve2019,grafana,auth-bypass,dos\""
	Categories StringSlice `json:"categories,omitempty" yaml:"categories,omitempty" jsonschema:"title=categories of the template,description=Any categories for the template"`
	// description: |
	//     当前应用程序肯定不包含的程序
	//
	// examples:
	//   - name: Example excludes
	//     value: "nginx"
	Excludes StringSlice `json:"excludes,omitempty" yaml:"excludes,omitempty" jsonschema:"title=excludes of the template,description=Any excludes for the template"`
	// description: |
	//     当前应用程序关联的程序
	//
	// examples:
	//   - name: Example excludes
	//     value: "nginx"
	Implies StringSlice `json:"implies,omitempty" yaml:"implies,omitempty" jsonschema:"title=implies of the template,description=Any implies for the template"`
	// description: |
	//   模板的说明，您可以在此处了解模板的实际功能
	//
	// examples:
	//   - value: "\"Bower is a package manager which stores package information in the bower.json file\""
	//   - value: "\"Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations\""
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,example=Bower is a package manager which stores package information in the bower.json file"`
	// description: |
	//   模板的引用，包含与模板相关的链接
	//
	// examples:
	//   - value: >
	//       []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
	Reference StringSlice `json:"reference,omitempty" yaml:"reference,omitempty" jsonschema:"title=references for the template,description=Links relevant to the template"`
	// description: |
	//   模板的元数据,，定义请求的相关参数，暂时不用
	// examples:
	//   - value: >
	//       map[string]string{"customField1":"customValue1"}
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template"`
	// description: |
	//		标准命名
	CPE string `json:"cpe,omitempty" yaml:"cpe,omitempty" jsonschema:"title=cpe info for the template,description=cpe information for the template"`
	// description: |
	//   图标
	Icon string `json:"icon,omitempty" yaml:"icon,omitempty" jsonschema:"title=icon info for the template,description=icon information for the template"`
	// description: |
	//   包含有关模板的分类信息
	Classification StringSlice `json:"classification,omitempty" yaml:"classification,omitempty" jsonschema:"title=classification info for the template,description=Classification information for the template"`
}
