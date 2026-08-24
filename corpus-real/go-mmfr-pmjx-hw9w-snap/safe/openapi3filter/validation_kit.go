package openapi3filter

import (
	"context"
	"encoding/json"
	"net/http"
)

































type ErrorEncoder func(ctx context.Context, err error, w http.ResponseWriter)




type StatusCoder interface {
	StatusCode() int
}




type Headerer interface {
	Headers() http.Header
}








func DefaultErrorEncoder(_ context.Context, err error, w http.ResponseWriter) {
	contentType, body := "text/plain; charset=utf-8", []byte(err.Error())
	if marshaler, ok := err.(json.Marshaler); ok {
		if jsonBody, marshalErr := marshaler.MarshalJSON(); marshalErr == nil {
			contentType, body = "application/json; charset=utf-8", jsonBody
		}
	}
	w.Header().Set("Content-Type", contentType)
	if headerer, ok := err.(Headerer); ok {
		for k, values := range headerer.Headers() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
	}
	code := http.StatusInternalServerError
	if sc, ok := err.(StatusCoder); ok {
		code = sc.StatusCode()
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}
