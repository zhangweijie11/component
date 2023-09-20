package matchers

import (
	"github.com/Knetic/govaluate"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/expressions"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/dsl"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/utils"
	"gitlab.example.com/zhangweijie/tool-sdk/middleware/logger"
	"strings"
)

// MatchStatusCode 匹配状态码
func (matcher *Matcher) MatchStatusCode(statusCode int) bool {
	// 状态码不支持 AND 条件
	for _, status := range matcher.Status {
		// 如果没有匹配到就继续
		if statusCode != status {
			continue
		}
		// 如果匹配到了直接返回
		return true
	}
	return false
}

// MatchSize 匹配模块长度
func (matcher *Matcher) MatchSize(length int) bool {
	// 长度不支持 AND 条件
	for _, size := range matcher.Size {
		// 如果没有匹配到就继续
		if length != size {
			continue
		}
		// 如果匹配到了就直接返回
		return true
	}
	return false
}

// MatchWords 匹配关键字
func (matcher *Matcher) MatchWords(corpus string, data map[string]interface{}) (bool, []string) {
	if matcher.CaseInsensitive {
		corpus = strings.ToLower(corpus)
	}

	var matchedWords []string
	for i, word := range matcher.Words {
		if data == nil {
			data = make(map[string]interface{})
		}

		var err error
		word, err = expressions.Evaluate(word, data)
		// 如果执行规则表达式出现问题，并且匹配器条件是 AND，表示该匹配器失败
		if err != nil {
			if matcher.condition == ANDCondition {
				return false, []string{}
			}
		}
		// 如果没匹配到，那么看该匹配器的条件，如果是 AND 那么表示该匹配器失败，如果是 OR 则继续匹配剩下的规则
		if !strings.Contains(corpus, word) {
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// 如果匹配器条件是 OR 并且不需要匹配全部规则，那么匹配到第一个结果就可以返回
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, []string{word}
		}
		matchedWords = append(matchedWords, word)

		// 如果已经执行到规则集的最后一个并且不需要匹配到全部规则，那么返回匹配到的数据即可，因为能执行到这一步意味着至少会有一个规则被匹配到
		if len(matcher.Words)-1 == i && !matcher.MatchAll {
			return true, matchedWords
		}
	}
	// 需要匹配所有规则并且存在匹配到的规则集则直接返回
	if len(matchedWords) > 0 && matcher.MatchAll {
		return true, matchedWords
	}
	return false, []string{}
}

// MatchRegex 匹配正则表达式
func (matcher *Matcher) MatchRegex(corpus string) (bool, []string) {
	var matchedRegexes []string
	for i, regex := range matcher.regexCompiled {
		// 如果没有匹配到正则表达式并且匹配器条件为 AND 则该匹配器失败
		if !regex.MatchString(corpus) {
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		currentMatches := regex.FindAllString(corpus, -1)
		// 如果匹配器条件是 OR 并且不需要匹配全部规则，那么匹配到第一个结果就可以返回
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, currentMatches
		}

		matchedRegexes = append(matchedRegexes, currentMatches...)

		// 如果已经执行到规则集的最后一个并且不需要匹配到全部规则，那么返回匹配到的数据即可，因为能执行到这一步意味着至少会有一个规则被匹配到
		if len(matcher.regexCompiled)-1 == i && !matcher.MatchAll {
			return true, matchedRegexes
		}
	}
	if len(matchedRegexes) > 0 && matcher.MatchAll {
		return true, matchedRegexes
	}
	return false, []string{}
}

// MatchBinary 匹配二进制数据
func (matcher *Matcher) MatchBinary(corpus string) (bool, []string) {
	var matchedBinary []string
	for i, binary := range matcher.binaryDecoded {
		if !strings.Contains(corpus, binary) {
			// 如果没有匹配到二进制数据并且匹配器条件为 AND 则该匹配器失败
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// 如果匹配器条件是 OR 并且不需要匹配全部规则，那么匹配到第一个结果就可以返回
		if matcher.condition == ORCondition {
			return true, []string{binary}
		}

		matchedBinary = append(matchedBinary, binary)

		// 如果已经执行到规则集的最后一个并且不需要匹配到全部规则，那么返回匹配到的数据即可，因为能执行到这一步意味着至少会有一个规则被匹配到
		if len(matcher.Binary)-1 == i {
			return true, matchedBinary
		}
	}
	return false, []string{}
}

// MatchDSL 匹配 DSL
func (matcher *Matcher) MatchDSL(data map[string]interface{}) bool {
	for i, expression := range matcher.dslCompiled {
		if varErr := expressions.ContainsUnresolvedVariables(expression.String()); varErr != nil {
			resolvedExpression, err := expressions.Evaluate(expression.String(), data)
			if err != nil {
				return false
			}
			expression, err = govaluate.NewEvaluableExpressionWithFunctions(resolvedExpression, dsl.HelperFunctions)
			if err != nil {
				return false
			}
		}
		result, err := expression.Evaluate(data)
		if err != nil {
			if matcher.condition == ANDCondition {
				return false
			}
			continue
		}

		if boolResult, ok := result.(bool); !ok {
			continue
		} else if !boolResult {
			// 如果没有匹配到 DSL 并且匹配器条件为 AND 则该匹配器失败
			switch matcher.condition {
			case ANDCondition:
				return false
			case ORCondition:
				continue
			}
		}

		// 如果匹配器条件是 OR 并且不需要匹配全部规则，那么匹配到第一个结果就可以返回
		if matcher.condition == ORCondition {
			return true
		}

		// 如果已经执行到规则集的最后一个并且不需要匹配到全部规则，那么返回匹配到的数据即可，因为能执行到这一步意味着至少会有一个规则被匹配到
		if len(matcher.dslCompiled)-1 == i {
			return true
		}
	}
	return false
}

// Match 通用匹配
func (matcher *Matcher) Match(data map[string]interface{}) (bool, []string) {
	item, ok := GetMatchPart(matcher.GetMatcherPartType(), data)
	if !ok && matcher.Type.MatcherType != DSLMatcher {
		logger.Warn("无效匹配")
	}

	switch matcher.GetMatcherType() {
	case StatusMatcher:
		statusCode, ok := utils.GetStatusCode(data)
		if !ok {
			return false, nil
		} else {
			if matcher.MatchStatusCode(statusCode) {
				return true, nil
			}
		}
	case SizeMatcher:
		if matcher.MatchSize(len(item)) {
			return true, nil
		}
	case WordsMatcher:
		if ok, _ := matcher.MatchWords(item, data); ok {
			return true, nil
		}
	case RegexMatcher:
		if ok, _ := matcher.MatchRegex(item); ok {
			return true, nil
		}
	case DSLMatcher:
		if ok := matcher.MatchDSL(data); ok {
			return true, nil
		}
	case BinaryMatcher:
		if ok, _ := matcher.MatchBinary(item); ok {
			return true, nil
		}
	}

	return false, nil
}
