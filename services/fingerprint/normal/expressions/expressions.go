package expressions

import (
	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/fasttemplate"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/dsl"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/utils"
	"strings"
)

const (
	// General marker (open/close)
	General = "§"
	// ParenthesisOpen 占位符开头
	ParenthesisOpen = "{{"
	// ParenthesisClose 占位符结尾
	ParenthesisClose = "}}"
)

// Evaluate 检查匹配项是否包含动态变量，对于找到的每个变量，将检查它是否是一个表达式并且可以编译，计算后返回结果
func Evaluate(data string, base map[string]interface{}) (string, error) {
	return evaluate(data, base)
}

// Replace 将模板中的占位符替换为动态值
func Replace(template string, values map[string]interface{}) string {
	valuesMap := make(map[string]interface{}, len(values))
	for k, v := range values {
		valuesMap[k] = utils.ToString(v)
	}
	replaced := fasttemplate.ExecuteStringStd(template, ParenthesisOpen, ParenthesisClose, valuesMap)
	final := fasttemplate.ExecuteStringStd(replaced, General, General, valuesMap)
	return final
}

// ReplaceOne 将模板中的一个占位符替换为一个动态值
func ReplaceOne(template string, key string, value interface{}) string {
	data := replaceOneWithMarkers(template, key, value, ParenthesisOpen, ParenthesisClose)
	return replaceOneWithMarkers(data, key, value, General, General)
}

// replaceOneWithMarkers 执行一次性替换的帮助程序函数
func replaceOneWithMarkers(template, key string, value interface{}, openMarker, closeMarker string) string {
	return strings.Replace(template, openMarker+key+closeMarker, utils.ToString(value), 1)
}

// maxIterations 避免无限循环
const maxIterations = 250

// 查找表达式
func findExpressions(data, OpenMarker, CloseMarker string, base map[string]interface{}) []string {
	var (
		iterations int
		exps       []string
	)
	for {
		// 检查是否达到了最大迭代次数
		if iterations > maxIterations {
			break
		}
		iterations++
		// 尝试查找开放标记
		indexOpenMarker := strings.Index(data, OpenMarker)
		if indexOpenMarker < 0 {
			break
		}

		indexOpenMarkerOffset := indexOpenMarker + len(OpenMarker)

		shouldSearchCloseMarker := true
		closeMarkerFound := false
		innerData := data
		var potentialMatch string
		var indexCloseMarker, indexCloseMarkerOffset int
		skip := indexOpenMarkerOffset
		for shouldSearchCloseMarker {
			// 尝试查找接近标记
			indexCloseMarker = utils.IndexAt(innerData, CloseMarker, skip)
			if indexCloseMarker < 0 {
				shouldSearchCloseMarker = false
				continue
			}
			indexCloseMarkerOffset = indexCloseMarker + len(CloseMarker)

			potentialMatch = innerData[indexOpenMarkerOffset:indexCloseMarker]
			if isExpression(potentialMatch, base) {
				closeMarkerFound = true
				shouldSearchCloseMarker = false
				exps = append(exps, potentialMatch)
			} else {
				skip = indexCloseMarkerOffset
			}
		}

		if closeMarkerFound {
			// move after the close marker
			data = data[indexCloseMarkerOffset:]
		} else {
			// move after the open marker
			data = data[indexOpenMarkerOffset:]
		}
	}
	return exps
}

// 判断是不是合法的表达式
func isExpression(data string, base map[string]interface{}) bool {
	if _, err := govaluate.NewEvaluableExpression(data); err == nil {
		if utils.ContainsAny(data, getFunctionsNames(base)...) {
			return true
		} else if utils.ContainsAny(data, dsl.FunctionNames...) {
			return true
		}
		return false
	}
	_, err := govaluate.NewEvaluableExpressionWithFunctions(data, dsl.HelperFunctions)
	return err == nil
}

// 获取方法名
func getFunctionsNames(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// 执行编译后的表达式
func evaluate(data string, base map[string]interface{}) (string, error) {
	// 替换简单占位符
	data = Replace(data, base)

	// 表达式示例:
	// - 简单的表达式: 简单的键值对  比如 len(body)==10或者 title==test
	// - 正则表达式: [\d+]
	// - DSL: contains(body, "test"),表示在 body 中有 test 这个字符串
	expressions := findExpressions(data, ParenthesisOpen, ParenthesisClose, base)
	for _, expression := range expressions {
		// 将变量占位符替换为值
		expression = Replace(expression, base)
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.HelperFunctions)
		if err != nil {
			continue
		}
		result, err := compiled.Evaluate(base)
		if err != nil {
			continue
		}
		data = ReplaceOne(data, expression, result)
	}
	return data, nil
}
