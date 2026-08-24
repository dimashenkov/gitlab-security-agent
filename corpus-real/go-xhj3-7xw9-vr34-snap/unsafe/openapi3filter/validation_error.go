package openapi3filter

import (
	"bytes"
	"strconv"
)




type ValidationError struct {

	Id string `json:"id,omitempty" yaml:"id,omitempty"`

	Status int `json:"status,omitempty" yaml:"status,omitempty"`

	Code string `json:"code,omitempty" yaml:"code,omitempty"`

	Title string `json:"title,omitempty" yaml:"title,omitempty"`

	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`

	Source *ValidationErrorSource `json:"source,omitempty" yaml:"source,omitempty"`
}


type ValidationErrorSource struct {

	Pointer string `json:"pointer,omitempty" yaml:"pointer,omitempty"`

	Parameter string `json:"parameter,omitempty" yaml:"parameter,omitempty"`
}

var _ error = &ValidationError{}


func (e *ValidationError) Error() string {
	b := bytes.NewBufferString("[")
	if e.Status != 0 {
		b.WriteString(strconv.Itoa(e.Status))
	}
	b.WriteString("]")
	b.WriteString("[")
	if e.Code != "" {
		b.WriteString(e.Code)
	}
	b.WriteString("]")
	b.WriteString("[")
	if e.Id != "" {
		b.WriteString(e.Id)
	}
	b.WriteString("]")
	b.WriteString(" ")
	if e.Title != "" {
		b.WriteString(e.Title)
		b.WriteString(" ")
	}
	if e.Detail != "" {
		b.WriteString("| ")
		b.WriteString(e.Detail)
		b.WriteString(" ")
	}
	if e.Source != nil {
		b.WriteString("[source ")
		if e.Source.Parameter != "" {
			b.WriteString("parameter=")
			b.WriteString(e.Source.Parameter)
		} else if e.Source.Pointer != "" {
			b.WriteString("pointer=")
			b.WriteString(e.Source.Pointer)
		}
		b.WriteString("]")
	}

	if b.Len() == 0 {
		return "no error"
	}
	return b.String()
}


func (e *ValidationError) StatusCode() int {
	return e.Status
}
