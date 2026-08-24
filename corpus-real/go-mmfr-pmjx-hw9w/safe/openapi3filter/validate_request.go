package openapi3filter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)



var ErrAuthenticationServiceMissing = errors.New("missing AuthenticationFunc")


var ErrInvalidRequired = errors.New("value is required but missing")


var ErrInvalidEmptyValue = errors.New("empty value is not allowed")







func ValidateRequest(ctx context.Context, input *RequestValidationInput) error {
	var me openapi3.MultiError

	options := input.Options
	if options == nil {
		options = &Options{}
	}
	route := input.Route
	operation := route.Operation
	operationParameters := operation.Parameters
	pathItemParameters := route.PathItem.Parameters


	security := operation.Security

	if security == nil {

		security = &route.Spec.Security
	}
	if security != nil {
		if err := ValidateSecurityRequirements(ctx, input, *security); err != nil {
			if !options.MultiError {
				return err
			}
			me = append(me, err)
		}
	}


	for _, parameterRef := range pathItemParameters {
		parameter := parameterRef.Value
		if operationParameters != nil {
			if override := operationParameters.GetByInAndName(parameter.In, parameter.Name); override != nil {
				continue
			}
		}

		if err := ValidateParameter(ctx, input, parameter); err != nil {
			if !options.MultiError {
				return err
			}
			me = append(me, err)
		}
	}


	for _, parameter := range operationParameters {
		if options.ExcludeRequestQueryParams && parameter.Value.In == openapi3.ParameterInQuery {
			continue
		}
		if err := ValidateParameter(ctx, input, parameter.Value); err != nil {
			if !options.MultiError {
				return err
			}
			me = append(me, err)
		}
	}


	requestBody := operation.RequestBody
	if !options.ExcludeRequestBody {

		if requestBody != nil {
			if err := ValidateRequestBody(ctx, input, requestBody.Value); err != nil {
				if !options.MultiError {
					return err
				}
				me = append(me, err)
			}
		}


		if options.RejectWhenRequestBodyNotSpecified && input.Request.ContentLength > 0 {
			err := &RequestError{
				Input: input,
				Err:   errors.New("request body not allowed for this request"),
			}
			if !options.MultiError {
				return err
			}
			me = append(me, err)
		}
	}

	if len(me) > 0 {
		return me
	}
	return nil
}


func appendToQueryValues[T any](q url.Values, parameterName string, v []T) {
	for _, i := range v {
		q.Add(parameterName, fmt.Sprint(i))
	}
}

func joinValues(values []any, sep string) string {
	strValues := make([]string, 0, len(values))
	for _, v := range values {
		strValues = append(strValues, fmt.Sprint(v))
	}
	return strings.Join(strValues, sep)
}


func populateDefaultQueryParameters(q url.Values, parameterName string, value any, explode bool) {
	switch t := value.(type) {
	case []any:
		if explode {
			appendToQueryValues(q, parameterName, t)
		} else {
			q.Add(parameterName, joinValues(t, ","))
		}
	default:
		q.Add(parameterName, fmt.Sprint(value))
	}
}






func ValidateParameter(ctx context.Context, input *RequestValidationInput, parameter *openapi3.Parameter) error {
	if parameter.Schema == nil && parameter.Content == nil {



		return nil
	}

	options := input.Options
	if options == nil {
		options = &Options{}
	}

	var value any
	var err error
	var found bool
	var schema *openapi3.Schema


	if parameter.Content != nil {
		if value, schema, found, err = decodeContentParameter(parameter, input); err != nil {
			return &RequestError{Input: input, Parameter: parameter, Err: err}
		}
	} else {
		if value, found, err = decodeStyledParameter(parameter, input); err != nil {
			return &RequestError{Input: input, Parameter: parameter, Err: err}
		}
		schema = parameter.Schema.Value
	}


	if !options.SkipSettingDefaults && value == nil && schema != nil {
		value = schema.Default
		for _, subSchema := range schema.AllOf {
			if subSchema.Value.Default != nil {
				value = subSchema.Value.Default
				break
			}
		}

		if value != nil {
			req := input.Request
			switch parameter.In {
			case openapi3.ParameterInPath:


			case openapi3.ParameterInQuery:
				q := req.URL.Query()
				explode := parameter.Explode != nil && *parameter.Explode
				populateDefaultQueryParameters(q, parameter.Name, value, explode)
				req.URL.RawQuery = q.Encode()
			case openapi3.ParameterInHeader:
				req.Header.Add(parameter.Name, fmt.Sprint(value))
			case openapi3.ParameterInCookie:
				req.AddCookie(&http.Cookie{
					Name:  parameter.Name,
					Value: fmt.Sprint(value),
				})
			}
		}
	}


	if parameter.Required && !found {
		return &RequestError{Input: input, Parameter: parameter, Reason: ErrInvalidRequired.Error(), Err: ErrInvalidRequired}
	}

	if isNilValue(value) {
		if !parameter.AllowEmptyValue && found {
			return &RequestError{Input: input, Parameter: parameter, Reason: ErrInvalidEmptyValue.Error(), Err: ErrInvalidEmptyValue}
		}
		return nil
	}
	if schema == nil {

		return nil
	}

	var opts []openapi3.SchemaValidationOption
	if options.MultiError {
		opts = append(opts, openapi3.MultiErrors())
	}
	if options.customSchemaErrorFunc != nil {
		opts = append(opts, openapi3.SetSchemaErrorMessageCustomizer(options.customSchemaErrorFunc))
	}
	if input.Route != nil && input.Route.Spec.IsOpenAPI31OrLater() {
		opts = append(opts, openapi3.EnableJSONSchema2020())
	}
	if err = schema.VisitJSON(value, opts...); err != nil {
		return &RequestError{Input: input, Parameter: parameter, Err: err}
	}
	return nil
}

const prefixInvalidCT = "header Content-Type has unexpected value"





func ValidateRequestBody(ctx context.Context, input *RequestValidationInput, requestBody *openapi3.RequestBody) error {
	var (
		req  = input.Request
		data []byte
	)

	options := input.Options
	if options == nil {
		options = &Options{}
	}

	if req.Body != http.NoBody && req.Body != nil {
		defer req.Body.Close()
		var err error
		if data, err = io.ReadAll(req.Body); err != nil {
			return &RequestError{
				Input:       input,
				RequestBody: requestBody,
				Reason:      "reading failed",
				Err:         err,
			}
		}

		req.Body = nil
		if req.GetBody != nil {
			if req.Body, err = req.GetBody(); err != nil {
				req.Body = nil
			}
		}
		if req.Body == nil {
			req.ContentLength = int64(len(data))
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			req.Body, _ = req.GetBody()
		}
	}

	if len(data) == 0 {
		if requestBody.Required {
			return &RequestError{Input: input, RequestBody: requestBody, Err: ErrInvalidRequired}
		}
		return nil
	}

	content := requestBody.Content
	if len(content) == 0 {

		return nil
	}

	inputMIME := req.Header.Get(headerCT)
	contentType := requestBody.Content.Get(inputMIME)
	if contentType == nil {
		return &RequestError{
			Input:       input,
			RequestBody: requestBody,
			Reason:      fmt.Sprintf("%s %q", prefixInvalidCT, inputMIME),
		}
	}

	if contentType.Schema == nil {

		return nil
	}

	encFn := func(name string) *openapi3.Encoding { return contentType.Encoding[name] }
	mediaType, value, err := decodeBody(bytes.NewReader(data), req.Header, contentType.Schema, encFn)
	if err != nil {
		return &RequestError{
			Input:       input,
			RequestBody: requestBody,
			Reason:      "failed to decode request body",
			Err:         err,
		}
	}

	defaultsSet := false
	var opts []openapi3.SchemaValidationOption
	opts = append(opts, openapi3.VisitAsRequest())
	if !options.SkipSettingDefaults {
		opts = append(opts, openapi3.DefaultsSet(func() { defaultsSet = true }))
	}
	if options.MultiError {
		opts = append(opts, openapi3.MultiErrors())
	}
	if options.customSchemaErrorFunc != nil {
		opts = append(opts, openapi3.SetSchemaErrorMessageCustomizer(options.customSchemaErrorFunc))
	}
	if options.ExcludeReadOnlyValidations {
		opts = append(opts, openapi3.DisableReadOnlyValidation())
	}
	if options.RegexCompiler != nil {
		opts = append(opts, openapi3.SetSchemaRegexCompiler(options.RegexCompiler))
	}

	opts = append(opts, options.SchemaValidationOptions...)
	if input.Route != nil && input.Route.Spec.IsOpenAPI31OrLater() {
		opts = append(opts, openapi3.EnableJSONSchema2020())
	}


	if err := contentType.Schema.Value.VisitJSON(value, opts...); err != nil {
		schemaId := getSchemaIdentifier(contentType.Schema)
		schemaId = prependSpaceIfNeeded(schemaId)
		return &RequestError{
			Input:       input,
			RequestBody: requestBody,
			Reason:      fmt.Sprintf("doesn't match schema%s", schemaId),
			Err:         err,
		}
	}

	if defaultsSet {
		var err error
		if data, err = encodeBody(value, mediaType); err != nil {
			return &RequestError{
				Input:       input,
				RequestBody: requestBody,
				Reason:      "rewriting failed",
				Err:         err,
			}
		}

		if req.Body != nil {
			req.Body.Close()
		}
		req.ContentLength = int64(len(data))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		req.Body, _ = req.GetBody()
	}

	return nil
}




func ValidateSecurityRequirements(ctx context.Context, input *RequestValidationInput, srs openapi3.SecurityRequirements) error {
	if len(srs) == 0 {
		return nil
	}
	var errs []error
	for _, sr := range srs {
		if err := validateSecurityRequirement(ctx, input, sr); err != nil {
			if len(errs) == 0 {
				errs = make([]error, 0, len(srs))
			}
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return &SecurityRequirementsError{
		SecurityRequirements: srs,
		Errors:               errs,
	}
}


func validateSecurityRequirement(ctx context.Context, input *RequestValidationInput, securityRequirement openapi3.SecurityRequirement) error {
	names := make([]string, 0, len(securityRequirement))
	for name := range securityRequirement {
		names = append(names, name)
	}
	slices.Sort(names)


	options := input.Options
	if options == nil {
		options = &Options{}
	}
	f := options.AuthenticationFunc
	if f == nil {
		return ErrAuthenticationServiceMissing
	}

	var securitySchemes openapi3.SecuritySchemes
	if components := input.Route.Spec.Components; components != nil {
		securitySchemes = components.SecuritySchemes
	}


	var data []byte

	if input.Request != nil && input.Request.Body != http.NoBody && input.Request.Body != nil {
		defer input.Request.Body.Close()

		var err error
		if data, err = io.ReadAll(input.Request.Body); err != nil {
			return &RequestError{
				Input:  input,
				Reason: "reading failed",
				Err:    err,
			}
		}
	}


	for _, name := range names {
		var securityScheme *openapi3.SecurityScheme
		if securitySchemes != nil {
			if ref := securitySchemes[name]; ref != nil {
				securityScheme = ref.Value
			}
		}
		if securityScheme == nil {
			return &RequestError{
				Input: input,
				Err:   fmt.Errorf("security scheme %q is not declared", name),
			}
		}
		scopes := securityRequirement[name]


		if data != nil {
			var err error

			input.Request.Body = nil
			if input.Request.GetBody != nil {
				if input.Request.Body, err = input.Request.GetBody(); err != nil {
					input.Request.Body = nil
				}
			}
			if input.Request.Body == nil {
				input.Request.ContentLength = int64(len(data))
				input.Request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(data)), nil
				}
				input.Request.Body, _ = input.Request.GetBody()
			}
		}

		if err := f(ctx, &AuthenticationInput{
			RequestValidationInput: input,
			SecuritySchemeName:     name,
			SecurityScheme:         securityScheme,
			Scopes:                 scopes,
		}); err != nil {
			return err
		}
	}


	if data != nil {
		var err error

		input.Request.Body = nil
		if input.Request.GetBody != nil {
			if input.Request.Body, err = input.Request.GetBody(); err != nil {
				input.Request.Body = nil
			}
		}
		if input.Request.Body == nil {
			input.Request.ContentLength = int64(len(data))
			input.Request.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			input.Request.Body, _ = input.Request.GetBody()
		}
	}
	return nil
}
