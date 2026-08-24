package openapi3filter

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"
)




type AuthenticationFunc func(context.Context, *AuthenticationInput) error


func NoopAuthenticationFunc(context.Context, *AuthenticationInput) error { return nil }

var _ AuthenticationFunc = NoopAuthenticationFunc

type ValidationHandler struct {
	Handler            http.Handler
	AuthenticationFunc AuthenticationFunc
	File               string
	ErrorEncoder       ErrorEncoder
	router             routers.Router
}

func (h *ValidationHandler) Load() error {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(h.File)
	if err != nil {
		return err
	}
	if err := doc.Validate(loader.Context); err != nil {
		return err
	}
	if h.router, err = legacyrouter.NewRouter(doc); err != nil {
		return err
	}


	if h.Handler == nil {
		h.Handler = http.DefaultServeMux
	}
	if h.AuthenticationFunc == nil {
		h.AuthenticationFunc = NoopAuthenticationFunc
	}
	if h.ErrorEncoder == nil {
		h.ErrorEncoder = DefaultErrorEncoder
	}

	return nil
}

func (h *ValidationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handled := h.before(w, r); handled {
		return
	}

	h.Handler.ServeHTTP(w, r)
}


func (h *ValidationHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handled := h.before(w, r); handled {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *ValidationHandler) before(w http.ResponseWriter, r *http.Request) (handled bool) {
	if err := h.validateRequest(r); err != nil {
		h.ErrorEncoder(r.Context(), err, w)
		return true
	}
	return false
}

func (h *ValidationHandler) validateRequest(r *http.Request) error {

	route, pathParams, err := h.router.FindRoute(r)
	if err != nil {
		return err
	}

	options := &Options{
		AuthenticationFunc: h.AuthenticationFunc,
	}


	requestValidationInput := &RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
		Options:    options,
	}
	if err = ValidateRequest(r.Context(), requestValidationInput); err != nil {
		return err
	}

	return nil
}
