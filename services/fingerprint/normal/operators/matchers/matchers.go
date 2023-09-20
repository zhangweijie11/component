package matchers

import (
	"github.com/Knetic/govaluate"
	"regexp"
)

// Matcher is used to match a part in the output from a protocol.
type Matcher struct {
	// description: |
	//   匹配器的名称,名称应为小写,不得包含空格或下划线 （_）
	// examples:
	//   - value: "\"cookie-matcher\""
	Name string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"title=name of the matcher,description=Name of the matcher"`
	// description: |
	//   匹配器的类型:status,size,word,regex,binary,dsl
	Type MatcherTypeHolder `yaml:"type" json:"type" jsonschema:"title=type of matcher,description=Type of the matcher,enum=status,enum=size,enum=word,enum=regex,enum=binary,enum=dsl"`
	// description: |
	//   请求响应以匹配数据的部分
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part MatcherPartTypeHolder `yaml:"part,omitempty" json:"part,omitempty" jsonschema:"title=part of response to match,description=Part of response to match data from"`
	// description: |
	//   两个匹配器变量之间的可选条件。默认情况下，假定条件为 OR
	// values:
	//   - "and"
	//   - "or"
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty" jsonschema:"title=condition between matcher variables,description=Condition between the matcher variables,enum=and,enum=or"`
	// description: |
	//   是否应反转匹配 仅当条件不为真时，它才会匹配
	Negative bool `yaml:"negative,omitempty" json:"negative,omitempty" jsonschema:"title=negative specifies if match reversed,description=Negative specifies if the match should be reversed. It will only match if the condition is not true"`
	// description: |
	//   响应状态代码
	// examples:
	//   - value: >
	//       []int{200, 302}
	Status []int `yaml:"status,omitempty" json:"status,omitempty" jsonschema:"title=status to match,description=Status to match for the response"`
	// description: |
	//  响应大小
	// examples:
	//   - value: >
	//       []int{3029, 2042}
	Size []int `yaml:"size,omitempty" json:"size,omitempty" jsonschema:"title=acceptable size for response,description=Size is the acceptable size for the response"`
	// description: |
	//   关键词匹配
	// examples:
	//   - name: Match for Outlook mail protection domain
	//     value: >
	//       []string{"mail.protection.outlook.com"}
	//   - name: Match for application/json in response headers
	//     value: >
	//       []string{"application/json"}
	Words []string `yaml:"words,omitempty" json:"words,omitempty" jsonschema:"title=words to match in response,description= Words contains word patterns required to be present in the response part"`
	// description: |
	//   正则匹配
	// examples:
	//   - name: Match for Linkerd Service via Regex
	//     value: >
	//       []string{`(?mi)^Via\\s*?:.*?linkerd.*$`}
	//   - name: Match for Open Redirect via Location header
	//     value: >
	//       []string{`(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)example\\.com.*$`}
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty" jsonschema:"title=regex to match in response,description=Regex contains regex patterns required to be present in the response part"`
	// description: |
	//   二进制匹配
	// examples:
	//   - name: Match for Springboot Heapdump Actuator "JAVA PROFILE", "HPROF", "Gunzip magic byte"
	//     value: >
	//       []string{"4a4156412050524f46494c45", "4850524f46", "1f8b080000000000"}
	//   - name: Match for 7zip files
	//     value: >
	//       []string{"377ABCAF271C"}
	Binary []string `yaml:"binary,omitempty" json:"binary,omitempty" jsonschema:"title=binary patterns to match in response,description=Binary are the binary patterns required to be present in the response part"`
	// description: |
	//   DSL 匹配
	//   A list of these helper functions are available [here](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/).
	// examples:
	//   - name: DSL Matcher for package.json file
	//     value: >
	//       []string{"contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200"}
	//   - name: DSL Matcher for missing strict transport security header
	//     value: >
	//       []string{"!contains(tolower(all_headers), ''strict-transport-security'')"}
	DSL []string `yaml:"dsl,omitempty" json:"dsl,omitempty" jsonschema:"title=dsl expressions to match in response,description=DSL are the dsl expressions that will be evaluated as part of nuclei matching rules"`
	// description: |
	//   指定单词字段的编码
	// values:
	//   - "hex"
	Encoding string `yaml:"encoding,omitempty" json:"encoding,omitempty" jsonschema:"title=encoding for word field,description=Optional encoding for the word fields,enum=hex"`
	// description: |
	//   启用不区分大小写的匹配。默认值为false
	// values:
	//   - false
	//   - true
	CaseInsensitive bool `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty" jsonschema:"title=use case insensitive match,description=use case insensitive match"`
	// description: |
	//   启用所有匹配器值的匹配,默认值为false，如果 MatchAll 为 true 则会将所有的规则都跑一遍
	// values:
	//   - false
	//   - true
	MatchAll bool `yaml:"match-all,omitempty" json:"match-all,omitempty" jsonschema:"title=match all values,description=match all matcher values ignoring condition"`
	// 已编译匹配器的缓存数据
	condition       ConditionType
	matcherType     MatcherType
	matcherPartType MatcherPartType
	binaryDecoded   []string
	regexCompiled   []*regexp.Regexp
	dslCompiled     []*govaluate.EvaluableExpression
}
