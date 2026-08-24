package openapi3filter

import "github.com/getkin/kin-openapi/openapi3"


type Options struct {

	ExcludeRequestBody bool


	ExcludeRequestQueryParams bool


	ExcludeResponseBody bool


	ExcludeReadOnlyValidations bool


	ExcludeWriteOnlyValidations bool



	IncludeResponseStatus bool

	MultiError bool


	RegexCompiler openapi3.RegexCompilerFunc


	RejectWhenRequestBodyNotSpecified bool




	AuthenticationFunc AuthenticationFunc



	SkipSettingDefaults bool

	customSchemaErrorFunc CustomSchemaErrorFunc



	SchemaValidationOptions []openapi3.SchemaValidationOption
}


type CustomSchemaErrorFunc func(err *openapi3.SchemaError) string



func (o *Options) WithCustomSchemaErrorFunc(f CustomSchemaErrorFunc) {
	o.customSchemaErrorFunc = f
}
