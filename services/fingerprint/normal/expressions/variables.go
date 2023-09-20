package expressions

import (
	"errors"
	"github.com/Knetic/govaluate"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators/dsl"
	"regexp"
	"strings"
)

var (
	numericalExpressionRegex = regexp.MustCompile(`^[0-9+\-/\W]+$`)                                     // +-?/
	unresolvedVariablesRegex = regexp.MustCompile(`(?:%7[B|b]|\{){2}([^}]+)(?:%7[D|d]|\}){2}["'\)\}]*`) //  {{ to_lower('sdf')}} 大括号中的
)

// ContainsUnresolvedVariables 如果传递的输入包含未解析的 {{}} 变量，则返回带有变量名称的错误<pattern-here>
func ContainsUnresolvedVariables(items ...string) error {
	for _, data := range items {
		matches := unresolvedVariablesRegex.FindAllStringSubmatch(data, -1)
		if len(matches) == 0 {
			return nil
		}
		var unresolvedVariables []string
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			// 如果匹配项是表达式，则跳过
			if numericalExpressionRegex.MatchString(match[1]) {
				continue
			}
			// 如果它只包含文字或者可以从表达式引擎中求解
			if hasLiteralsOnly(match[1]) {
				continue
			}
			unresolvedVariables = append(unresolvedVariables, match[1])
		}
		if len(unresolvedVariables) > 0 {
			return errors.New("unresolved variables found: " + strings.Join(unresolvedVariables, ","))
		}
	}

	return nil
}

func hasLiteralsOnly(data string) bool {
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(data, dsl.HelperFunctions)
	if err != nil {
		return false
	}
	if err == nil && expr != nil {
		_, err = expr.Evaluate(nil)
		return err == nil
	}
	return true
}
