package matchers

// ConditionType 匹配器是否匹配到的条件
type ConditionType int

const (
	ANDCondition ConditionType = iota + 1
	ORCondition
)

// ConditionTypes 匹配器条件和字符串映射表
var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}
