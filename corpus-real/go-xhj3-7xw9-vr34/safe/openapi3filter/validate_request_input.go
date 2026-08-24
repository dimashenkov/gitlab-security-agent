package openapi3filter

import (
	"net/http"
	"net/url"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
)










type ContentParameterDecoder func(param *openapi3.Parameter, values []string) (any, *openapi3.Schema, error)

type RequestValidationInput struct {
	Request      *http.Request
	PathParams   map[string]string
	QueryParams  url.Values
	Route        *routers.Route
	Options      *Options
	ParamDecoder ContentParameterDecoder
}

func (input *RequestValidationInput) GetQueryParams() url.Values {
	q := input.QueryParams
	if q == nil {
		q = input.Request.URL.Query()
		input.QueryParams = q
	}
	return q
}
