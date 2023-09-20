package matchers

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"reflect"
	"strings"
)

var commonExpectedFields = []string{"Type", "Condition", "Name", "MatchAll", "Negative"}

// Validate 验证匹配器结构
func (matcher *Matcher) Validate() error {
	matcherMap := make(map[string]interface{})
	marshaledMatcher, err := yaml.Marshal(matcher)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(marshaledMatcher, &matcherMap); err != nil {
		return err
	}

	var expectedFields []string
	switch matcher.matcherType {
	case DSLMatcher:
		expectedFields = append(commonExpectedFields, "DSL")
	case StatusMatcher:
		expectedFields = append(commonExpectedFields, "Status", "Part")
	case SizeMatcher:
		expectedFields = append(commonExpectedFields, "Size", "Part")
	case WordsMatcher:
		expectedFields = append(commonExpectedFields, "Words", "Part", "Encoding", "CaseInsensitive")
	case BinaryMatcher:
		expectedFields = append(commonExpectedFields, "Binary", "Part", "Encoding", "CaseInsensitive")
	case RegexMatcher:
		expectedFields = append(commonExpectedFields, "Regex", "Part", "Encoding", "CaseInsensitive")
	}
	return checkFields(matcher, matcherMap, expectedFields...)
}

// Contains 判断切片是否包含某个元素
func Contains[T comparable](inputSlice []T, element T) bool {
	for _, inputValue := range inputSlice {
		if inputValue == element {
			return true
		}
	}

	return false
}

// 检查字段是否是限制内的字段
func checkFields(m *Matcher, matcherMap map[string]interface{}, expectedFields ...string) error {
	var foundUnexpectedFields []string

	for marshaledFieldName := range matcherMap {
		structFieldName, err := getFieldNameFromYamlTag(marshaledFieldName, *m)
		if err != nil {
			return err
		}
		if !Contains(expectedFields, structFieldName) {
			foundUnexpectedFields = append(foundUnexpectedFields, structFieldName)
		}
	}
	if len(foundUnexpectedFields) > 0 {
		return fmt.Errorf("matcher %s has unexpected fields: %s", m.matcherType, strings.Join(foundUnexpectedFields, ","))
	}
	return nil
}

// 获取字段的 tag
func getFieldNameFromYamlTag(tagName string, object interface{}) (string, error) {
	reflectType := reflect.TypeOf(object)
	if reflectType.Kind() != reflect.Struct {
		return "", errors.New("the object must be a struct")
	}
	for idx := 0; idx < reflectType.NumField(); idx++ {
		field := reflectType.Field(idx)
		tagParts := strings.Split(field.Tag.Get("yaml"), ",")
		if len(tagParts) > 0 && tagParts[0] == tagName {
			return field.Name, nil
		}
	}
	return "", fmt.Errorf("field %s not found", tagName)
}
