package extractors

// Extractor 用于使用正则表达式提取部分响应
type Extractor struct {
	// description: |
	//   提取程序的名称,名称应为小写,不得包含空格或下划线 （_）
	// examples:
	//   - value: "\"cookie-extractor\""
	Name string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"title=name of the extractor,description=Name of the extractor"`
	// description: |
	//   提取程序的类型:regex,kval,json,xpath,dsl
	Type ExtractorTypeHolder `json:"type" yaml:"type"`
	// description: |
	//   要从部件中提取的正则表达式模式
	//
	//   Go regex engine does not support lookaheads or lookbehinds, so as a result
	//   they are also not supported in nuclei.
	// examples:
	//   - name: Braintree Access Token Regex
	//     value: >
	//       []string{"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"}
	//   - name: Wordpress Author Extraction regex
	//     value: >
	//       []string{"Author:(?:[A-Za-z0-9 -\\_=\"]+)?<span(?:[A-Za-z0-9 -\\_=\"]+)?>([A-Za-z0-9]+)<\\/span>"}
	//官网示例：
	//extractors:
	//  - type: regex # type of the extractor
	//    part: body  # part of the response (header,body,all)
	//    regex:
	//      - "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"  # regex to use for extraction.
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty" jsonschema:"title=regex to extract from part,description=Regex to extract from part"`
	// description: |
	//   从正则表达式中提取的编号组
	// examples:
	//   - name: Example Regex Group
	//     value: "1"
	RegexGroup int `yaml:"group,omitempty" json:"group,omitempty" jsonschema:"title=group to extract from regex,description=Group to extract from regex"`
	// description: |
	//   从响应标头/Cookie 中提取 key: value / key=value 格式的数据
	//   KVAL 提取器输入不区分大小写，并且不支持输入中的破折号 （-），可以用下划线 （_） 替换
	// 	 For example, Content-Type should be replaced with content_type
	//
	//   A list of supported parts is available in docs for request types.
	// examples:
	//   - name: Extract Server Header From HTTP Response
	//     value: >
	//       []string{"server"}
	//   - name: Extracting value of PHPSESSID Cookie
	//     value: >
	//       []string{"phpsessid"}
	//   - name: Extracting value of Content-Type Cookie
	//     value: >
	//       []string{"content_type"}
	// 官网示例：
	//extractors:
	//  - type: kval # type of the extractor
	//    kval:
	//      - content_type # header/cookie value to extract from response
	KVal []string `yaml:"kval,omitempty" json:"kval,omitempty" jsonschema:"title=kval pairs to extract from response,description=Kval pairs to extract from response"`

	// description: |
	//   使用 jq 样式语法从 json 响应中提取数据
	//
	// examples:
	//   - value: >
	//       []string{".[] | .id"}
	//   - value: >
	//       []string{".batters | .batter | .[] | .id"}
	// 官网示例：
	// extractors:
	//      - type: json # type of the extractor
	//        part: body
	//        name: user
	//        json:
	//          - '.[] | .id'  # JQ like syntax for extraction
	JSON []string `yaml:"json,omitempty" json:"json,omitempty" jsonschema:"title=json jq expressions to extract data,description=JSON JQ expressions to evaluate from response part"`
	// description: |
	//    使用 XPath 表达式从 HTML 响应中提取项目
	//
	// examples:
	//   - value: >
	//       []string{"/html/body/div/p[2]/a"}
	// 官网示例：
	// extractors:
	//  - type: xpath # type of the extractor
	//    attribute: href # attribute value to extract (optional)
	//    xpath:
	//      - '/html/body/div/p[2]/a' # xpath value for extraction
	XPath []string `yaml:"xpath,omitempty" json:"xpath,omitempty" jsonschema:"title=html xpath expressions to extract data,description=XPath allows using xpath expressions to extract items from html response"`
	// description: |
	//   从响应 XPath 中提取的属性
	//
	// examples:
	//   - value: "\"href\""
	Attribute string `yaml:"attribute,omitempty" json:"attribute,omitempty" jsonschema:"title=optional attribute to extract from xpath,description=Optional attribute to extract from response XPath"`
	// description: |
	//   使用 DSL 表达式的数据提取
	// 官网示例：
	// extractors:
	//  - type: dsl  # type of the extractor
	//    dsl:
	//      - len(body) # dsl expression value to extract from response
	DSL []string `yaml:"dsl,omitempty" json:"dsl,omitempty" jsonschema:"title=dsl expressions to extract,description=Optional attribute to extract from response dsl"`

	// description: |
	//   求响应从中提取数据的部分， header,body,all,raw
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part string `yaml:"part,omitempty" json:"part,omitempty" jsonschema:"title=part of response to extract data from,description=Part of the request response to extract data from"`
	// description: |
	//   启用不区分大小写的提取。默认值为 false
	// values:
	//   - false
	//   - true
	CaseInsensitive bool `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty" jsonschema:"title=use case insensitive extract,description=use case insensitive extract"`
}
