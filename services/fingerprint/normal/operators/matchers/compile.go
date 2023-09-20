package matchers

import (
	"encoding/hex"
	"fmt"
	"github.com/Knetic/govaluate"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/dsl"
	"regexp"
	"strings"
)

// 移除字符串前后的括号
func removeOuterParentheses(input string) string {
	if len(input) < 2 {
		return input
	}

	start := 0
	end := len(input) - 1

	if input[start] == '(' && input[end] == ')' {
		start++
		end--
	}
	// 将字符串转换为可以编译的正则表达式
	escapedPattern := regexp.QuoteMeta(input[start : end+1])

	return escapedPattern
}

// CompileMatchers 编译匹配器
func (matcher *Matcher) CompileMatchers() error {
	var ok bool

	// 支持16进制
	if matcher.Encoding == "hex" {
		for i, word := range matcher.Words {
			if decoded, err := hex.DecodeString(word); err == nil && len(decoded) > 0 {
				matcher.Words[i] = string(decoded)
			}
		}
	}

	// 检查matcher类型
	matcherType, err := ToMatcherTypes(matcher.GetMatcherType().String())
	if err != nil {
		return fmt.Errorf("unknown matcher type specified: %s", matcher.Type)
	}
	matcher.matcherType = matcherType

	if err != nil {
		return fmt.Errorf("unknown matcher type specified: %s", matcher.Type)
	}

	// 验证 matcher 结构体
	if err = matcher.Validate(); err != nil {
		return nil
	}

	for _, regex := range matcher.Regex {
		compiled, err := regexp.Compile(removeOuterParentheses(regex))
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		matcher.regexCompiled = append(matcher.regexCompiled, compiled)
	}

	// 16进制字符串 ==> []bytes ==> string
	for _, value := range matcher.Binary {
		if decoded, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("could not hex decode binary: %s", value)
		} else {
			matcher.binaryDecoded = append(matcher.binaryDecoded, string(decoded))
		}
	}

	// Compile the dsl expressions
	for _, dslExpression := range matcher.DSL {
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, dsl.HelperFunctions)
		if err != nil {
			return &dsl.CompilationError{DslSignature: dslExpression, WrappedError: err}
		}
		matcher.dslCompiled = append(matcher.dslCompiled, compiledExpression)
	}

	// 设置条件
	if matcher.Condition != "" {
		matcher.condition, ok = ConditionTypes[matcher.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", matcher.Condition)
		}
	} else {
		matcher.condition = ORCondition
	}

	if matcher.CaseInsensitive {
		if matcher.GetMatcherType() != WordsMatcher {
			return fmt.Errorf("case-insensitive flag is supported only for 'word' matchers (not '%s')", matcher.Type)
		}
		for i := range matcher.Words {
			matcher.Words[i] = strings.ToLower(matcher.Words[i])
		}
	}
	return nil

}
