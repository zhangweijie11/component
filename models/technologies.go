package models

import (
	"gitlab.example.com/zhangweijie/tool-sdk/global"
	"gitlab.example.com/zhangweijie/tool-sdk/models"
	"gorm.io/datatypes"
)

type Technologies struct {
	ID                uint           `gorm:"column:id;primarykey" json:"id"`
	Name              string         `gorm:"column:name;size:256;index;not null;default:'';comment:名称" json:"name"`
	Version           string         `gorm:"column:version;size:128;index;not null;default:'';comment:版本" json:"version"`
	Categories        string         `gorm:"column:categories;size:128;index;not null;default:'';comment:类别" json:"categories"`
	Tags              string         `gorm:"column:tags;size:128;index;not null;default:'';comment:标签" json:"tags"`
	Info              datatypes.JSON `gorm:"column:info;type:json,not null;default='{}';not null;comment:简要信息" json:"info"`
	Method            string         `gorm:"column:method;size:32;index;not null;default:'GET';comment:请求方式" json:"method"`
	Path              string         `gorm:"column:path;size:256;index;not null;default:'';comment:请求路径" json:"path"`
	MatchersCondition string         `gorm:"column:matchers_condition;size:32;index;not null;default:'';comment:匹配器条件" json:"matchers_condition"`
	Matchers          datatypes.JSON `gorm:"column:matchers;type:json,not null;default='{}';not null;comment:匹配器" json:"matchers"`
	models.ComplexBaseModel
}

func (Technologies) TableName() string {
	return "technologies"
}

// CreateTechnology 创建指纹规则
func CreateTechnology(technology *Technologies) error {
	if err := global.Db.Create(technology).Error; err != nil {
		return err
	}

	return nil
}

// GetTechnologyFromName 根据 Name 查询指纹数据
func GetTechnologyFromName(name string) (Technologies, error) {
	var technology Technologies
	if err := global.Db.Model(&Technologies{}).Where("name = ?", name).First(&technology).Error; err != nil {
		return technology, err
	}

	return technology, nil
}

// GetAllTechnology 根据 Name 查询指纹数据
func GetAllTechnology() (*[]Technologies, error) {
	var technologies []Technologies
	if err := global.Db.Model(&Technologies{}).Find(&technologies).Error; err != nil {
		return &technologies, err
	}

	return &technologies, nil
}
