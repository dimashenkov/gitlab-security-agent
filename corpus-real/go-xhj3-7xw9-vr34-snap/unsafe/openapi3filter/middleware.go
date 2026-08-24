package openapi3filter

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"

	"github.com/getkin/kin-openapi/routers"
)


type Validator struct {
	router  routers.Router
	errFunc ErrFunc
	logFunc LogFunc
	strict  bool
	options Options
}


type ErrFunc func(ctx context.Context, w http.ResponseWriter, status int, code ErrCode, err error)


type LogFunc func(ctx context.Context, message string, err error)




type ErrCode int

const (

	ErrCodeOK = 0


	ErrCodeCannotFindRoute = iota


	ErrCodeRequestInvalid = iota


	ErrCodeResponseInvalid = iota
)

func (e ErrCode) responseText() string {
	switch e {
	case ErrCodeOK:
		return "OK"
	case ErrCodeCannotFindRoute:
		return "not found"
	case ErrCodeRequestInvalid:
		return "bad request"
	default:
		return "server error"
	}
}



func NewValidator(router routers.Router, options ...ValidatorOption) *Validator {
	v := &Validator{
		router: router,
		errFunc: func(_ context.Context, w http.ResponseWriter, status int, code ErrCode, _ error) {
			http.Error(w, code.responseText(), status)
		},
		logFunc: func(_ context.Context, message string, err error) {
			log.Printf("%s: %v", message, err)
		},
	}
	for i := range options {
		options[i](v)
	}
	return v
}



type ValidatorOption func(*Validator)





func OnErr(f ErrFunc) ValidatorOption {
	return func(v *Validator) {
		v.errFunc = f
	}
}




func OnLog(f LogFunc) ValidatorOption {
	return func(v *Validator) {
		v.logFunc = f
	}
}




func Strict(strict bool) ValidatorOption {
	return func(v *Validator) {
		v.strict = strict
	}
}


func ValidationOptions(options Options) ValidatorOption {
	return func(v *Validator) {
		v.options = options
	}
}



func (v *Validator) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		route, pathParams, err := v.router.FindRoute(r)
		if err != nil {
			v.logFunc(ctx, "validation error: failed to find route for "+r.URL.String(), err)
			v.errFunc(ctx, w, http.StatusNotFound, ErrCodeCannotFindRoute, err)
			return
		}
		requestValidationInput := &RequestValidationInput{
			Request:    r,
			PathParams: pathParams,
			Route:      route,
			Options:    &v.options,
		}
		if err = ValidateRequest(ctx, requestValidationInput); err != nil {
			v.logFunc(ctx, "invalid request", err)
			v.errFunc(ctx, w, http.StatusBadRequest, ErrCodeRequestInvalid, err)
			return
		}

		var wr responseWrapper
		if v.strict {
			wr = &strictResponseWrapper{w: w}
		} else {
			wr = newWarnResponseWrapper(w)
		}

		h.ServeHTTP(wr, r)

		if err = ValidateResponse(ctx, &ResponseValidationInput{
			RequestValidationInput: requestValidationInput,
			Status:                 wr.statusCode(),
			Header:                 wr.Header(),
			Body:                   io.NopCloser(bytes.NewBuffer(wr.bodyContents())),
			Options:                &v.options,
		}); err != nil {
			v.logFunc(ctx, "invalid response", err)
			if v.strict {
				v.errFunc(ctx, w, http.StatusInternalServerError, ErrCodeResponseInvalid, err)
			}
			return
		}

		if err = wr.flushBodyContents(); err != nil {
			v.logFunc(ctx, "failed to write response", err)
		}
	})
}

type responseWrapper interface {
	http.ResponseWriter



	flushBodyContents() error


	statusCode() int


	bodyContents() []byte
}

type warnResponseWrapper struct {
	w             http.ResponseWriter
	headerWritten bool
	status        int
	body          bytes.Buffer
	tee           io.Writer
}

func newWarnResponseWrapper(w http.ResponseWriter) *warnResponseWrapper {
	wr := &warnResponseWrapper{
		w: w,
	}
	wr.tee = io.MultiWriter(w, &wr.body)
	return wr
}


func (wr *warnResponseWrapper) Write(b []byte) (int, error) {
	if !wr.headerWritten {
		wr.WriteHeader(http.StatusOK)
	}
	return wr.tee.Write(b)
}


func (wr *warnResponseWrapper) WriteHeader(status int) {
	if !wr.headerWritten {


		wr.status = status
		wr.headerWritten = true
	}
	wr.w.WriteHeader(wr.status)
}


func (wr *warnResponseWrapper) Header() http.Header {
	return wr.w.Header()
}


func (wr *warnResponseWrapper) Flush() {


	if fl, ok := wr.w.(http.Flusher); ok {
		fl.Flush()
	}
}

func (wr *warnResponseWrapper) flushBodyContents() error {
	return nil
}

func (wr *warnResponseWrapper) statusCode() int {
	return wr.status
}

func (wr *warnResponseWrapper) bodyContents() []byte {
	return wr.body.Bytes()
}

type strictResponseWrapper struct {
	w             http.ResponseWriter
	headerWritten bool
	status        int
	body          bytes.Buffer
}


func (wr *strictResponseWrapper) Write(b []byte) (int, error) {
	if !wr.headerWritten {
		wr.WriteHeader(http.StatusOK)
	}
	return wr.body.Write(b)
}


func (wr *strictResponseWrapper) WriteHeader(status int) {
	if !wr.headerWritten {
		wr.status = status
		wr.headerWritten = true
	}
}


func (wr *strictResponseWrapper) Header() http.Header {
	return wr.w.Header()
}

func (wr *strictResponseWrapper) flushBodyContents() error {
	wr.w.WriteHeader(wr.status)
	_, err := wr.w.Write(wr.body.Bytes())
	return err
}

func (wr *strictResponseWrapper) statusCode() int {
	return wr.status
}

func (wr *strictResponseWrapper) bodyContents() []byte {
	return wr.body.Bytes()
}
