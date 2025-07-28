package entities

import (
	"fmt"
	"time"
)

type SavingGroup struct {
	Date       string    `json:"date"`
	DateCreate time.Time `json:"date_create"`
	Savings    []Saving  `json:"savings"`
}

func (sg *SavingGroup) FormatDate() {
	var err error
	sg.DateCreate, err = time.Parse("2006-01-02", sg.Date)
	if err != nil {
		fmt.Println(err)
	}
}

type Saving struct {
	GroupName string `json:"group_name"`
	Value     int64  `json:"value"`
}

type SavingsSummarized struct {
	DateCreate string `json:"date_create"`
	Value      int64  `json:"value"`
}
