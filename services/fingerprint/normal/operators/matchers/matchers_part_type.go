package matchers

import (
	"encoding/json"
	"errors"
	"github.com/alecthomas/jsonschema"
	"gitlab.example.com/zhangweijie/component/services/fingerprint/normal/utils"
	"strings"
)

// MatcherPartType 匹配器类型
type MatcherPartType int

// MatcherPartTypeHolder 匹配器匹配模块的内部类型
type MatcherPartTypeHolder struct {
	MatcherPartType MatcherPartType `mapping:"true"`
}

// name:MatcherPartType
const (
	UrlMatcherPart MatcherPartType = iota + 1
	JsMatcherPart
	DomMatcherPart
	AllMatcherPart
	BodyMatcherPart
	HeadersMatcherPart
	CookiesMatcherPart
	ScriptsMatcherPart
	MetaMatcherPart
	DNSMatcherPart
	CertIssuerMatcherPart
	StatusCodeMatcherPart
	TitleMatcherPart
	matchPartLimit
)

// MatcherPartTypes 匹配模块和字符串的对照
var MatcherPartTypes = map[MatcherPartType]string{
	UrlMatcherPart:        "url",
	JsMatcherPart:         "js",
	DomMatcherPart:        "dom",
	AllMatcherPart:        "all",
	BodyMatcherPart:       "body",
	HeadersMatcherPart:    "headers",
	CookiesMatcherPart:    "cookies",
	ScriptsMatcherPart:    "scripts",
	MetaMatcherPart:       "meta",
	DNSMatcherPart:        "dns",
	CertIssuerMatcherPart: "cert_issuer",
	StatusCodeMatcherPart: "status_code",
	TitleMatcherPart:      "title",
}

// GetMatchPart 根据匹配器匹配模块获取相对应的字符串
func GetMatchPart(part MatcherPartType, data map[string]interface{}) (string, bool) {
	var itemStr string
	switch part {
	case AllMatcherPart:
		builder := &strings.Builder{}
		builder.WriteString(utils.ToString(data["body"]))
		builder.WriteString(utils.ToString(data["headers"]))
		itemStr = builder.String()
	default:
		item, ok := data[part.String()]
		if !ok {
			return "", false
		}
		itemStr = utils.ToString(item)

	}

	return itemStr, true
}

// GetSupportedMatcherPartTypes 获取支持类型的列表
func GetSupportedMatcherPartTypes() []MatcherPartType {
	var result []MatcherPartType
	for index := MatcherPartType(1); index < matchPartLimit; index++ {
		result = append(result, index)
	}
	return result
}

// ToMatcherPartTypes 通过字符串获取匹配器匹配模块
func ToMatcherPartTypes(valueToMap string) (MatcherPartType, error) {
	normalizedValue := strings.TrimSpace(strings.ToLower(valueToMap))
	for key, currentValue := range MatcherPartTypes {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid matcher part type: " + valueToMap)
}

func (t MatcherPartType) String() string {
	return MatcherPartTypes[t]
}

func (holder *MatcherPartTypeHolder) String() string {
	return holder.MatcherPartType.String()
}

func (holder *MatcherPartTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of the matcher",
		Description: "Type of the matcher",
	}
	for _, types := range GetSupportedMatcherPartTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *MatcherPartTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.MatcherPartType.String())
}

func (holder *MatcherPartTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := ToMatcherPartTypes(s)
	if err != nil {
		return err
	}

	holder.MatcherPartType = computedType
	return nil
}

func (holder *MatcherPartTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.MatcherPartType.String(), nil
}

func (holder *MatcherPartTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := ToMatcherPartTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.MatcherPartType = computedType
	return nil
}
