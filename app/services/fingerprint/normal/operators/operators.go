package operators

import (
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/extractors"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/matchers"
)

// Operators contains the operators that can be applied on protocols
type Operators struct {
	// description: |
	//   匹配器之间的条件。默认值为 OR
	// values:
	//   - "and"
	//   - "or"
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty" jsonschema:"title=condition between the matchers,description=Conditions between the matchers,enum=and,enum=or"`
	// description: |
	//   匹配器包含请求的检测机制，用于通过对请求或者响应执行模式匹配来确定请求是否成功
	//   多个匹配器可以与“matcher-condition”标志组合，该标志接受“and”或“or”作为参数
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty" jsonschema:"title=matchers to run on response,description=Detection mechanism to identify whether the request was successful by doing pattern matching"`
	// description: |
	//   提取程序包含用于标识和提取响应部分的提取机制
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty" jsonschema:"title=extractors to run on response,description=Extractors contains the extraction mechanism for the request to identify and extract parts of the response"`
}
