
package openapi3filter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)







func ValidateResponse(ctx context.Context, input *ResponseValidationInput) error {
	if req := input.RequestValidationInput.Request; req.Method == http.MethodHead {
		return nil
	}
	status := input.Status



	switch status {
	case http.StatusNotModified,
		http.StatusPermanentRedirect,
		http.StatusTemporaryRedirect,
		http.StatusMovedPermanently:
		return nil
	}
	route := input.RequestValidationInput.Route
	options := input.Options
	if options == nil {
		options = &Options{}
	}


	responses := route.Operation.Responses
	if responses.Len() == 0 {
		return nil
	}
	responseRef := responses.Status(status)
	if responseRef == nil {
		responseRef = responses.Default()
	}
	if responseRef == nil {

		if !options.IncludeResponseStatus {
			return nil
		}
		return &ResponseError{Input: input, Reason: "status is not supported"}
	}
	response := responseRef.Value
	if response == nil {
		return &ResponseError{Input: input, Reason: "response has not been resolved"}
	}

	var opts []openapi3.SchemaValidationOption
	if options.MultiError {
		opts = append(opts, openapi3.MultiErrors())
	}
	if options.customSchemaErrorFunc != nil {
		opts = append(opts, openapi3.SetSchemaErrorMessageCustomizer(options.customSchemaErrorFunc))
	}
	if options.ExcludeWriteOnlyValidations {
		opts = append(opts, openapi3.DisableWriteOnlyValidation())
	}

	opts = append(opts, options.SchemaValidationOptions...)
	if route.Spec.IsOpenAPI31OrLater() {
		opts = append(opts, openapi3.EnableJSONSchema2020())
	}

	headers := make([]string, 0, len(response.Headers))
	for k := range response.Headers {
		if k != headerCT {
			headers = append(headers, k)
		}
	}
	slices.Sort(headers)
	for _, headerName := range headers {
		headerRef := response.Headers[headerName]
		if err := validateResponseHeader(headerName, headerRef, input, opts); err != nil {
			return err
		}
	}

	if options.ExcludeResponseBody {

		return nil
	}

	content := response.Content
	if len(content) == 0 {

		return nil
	}

	inputMIME := input.Header.Get(headerCT)
	contentType := content.Get(inputMIME)
	if contentType == nil {
		return &ResponseError{
			Input:  input,
			Reason: fmt.Sprintf("response %s: %q", prefixInvalidCT, inputMIME),
		}
	}

	if contentType.Schema == nil {

		return nil
	}


	body := input.Body




	input.Body = nil


	defer body.Close()


	data, err := io.ReadAll(body)
	if err != nil {
		return &ResponseError{
			Input:  input,
			Reason: "failed to read response body",
			Err:    err,
		}
	}


	input.SetBodyBytes(data)

	encFn := func(name string) *openapi3.Encoding { return contentType.Encoding[name] }
	_, value, err := decodeBody(bytes.NewBuffer(data), input.Header, contentType.Schema, encFn)
	if err != nil {
		return &ResponseError{
			Input:  input,
			Reason: "failed to decode response body",
			Err:    err,
		}
	}


	if err := contentType.Schema.Value.VisitJSON(value, append(opts, openapi3.VisitAsResponse())...); err != nil {
		schemaId := getSchemaIdentifier(contentType.Schema)
		schemaId = prependSpaceIfNeeded(schemaId)
		return &ResponseError{
			Input:  input,
			Reason: fmt.Sprintf("response body doesn't match schema%s", schemaId),
			Err:    err,
		}
	}
	return nil
}

func validateResponseHeader(headerName string, headerRef *openapi3.HeaderRef, input *ResponseValidationInput, opts []openapi3.SchemaValidationOption) error {
	var err error
	var decodedValue any
	var found bool
	var sm *openapi3.SerializationMethod
	dec := &headerParamDecoder{header: input.Header}

	if sm, err = headerRef.Value.SerializationMethod(); err != nil {
		return &ResponseError{
			Input:  input,
			Reason: fmt.Sprintf("unable to get header %q serialization method", headerName),
			Err:    err,
		}
	}

	if decodedValue, found, err = decodeValue(dec, headerName, sm, headerRef.Value.Schema, headerRef.Value.Required); err != nil {
		return &ResponseError{
			Input:  input,
			Reason: fmt.Sprintf("unable to decode header %q value", headerName),
			Err:    err,
		}
	}

	if found {
		if err = headerRef.Value.Schema.Value.VisitJSON(decodedValue, opts...); err != nil {
			return &ResponseError{
				Input:  input,
				Reason: fmt.Sprintf("response header %q doesn't match schema", headerName),
				Err:    err,
			}
		}
	} else if headerRef.Value.Required {
		return &ResponseError{
			Input:  input,
			Reason: fmt.Sprintf("response header %q missing", headerName),
		}
	}
	return nil
}




func getSchemaIdentifier(schema *openapi3.SchemaRef) string {
	var id string

	if schema != nil {
		id = strings.TrimSpace(schema.Ref)
	}
	if id == "" && schema.Value != nil {
		id = strings.TrimSpace(schema.Value.Title)
	}

	return id
}

func prependSpaceIfNeeded(value string) string {
	if len(value) > 0 {
		value = " " + value
	}
	return value
}
