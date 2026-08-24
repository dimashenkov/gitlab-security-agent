package openapi3filter

import (
	"encoding/json"
	"fmt"
	"sync"
)

func encodeBody(body any, mediaType string) ([]byte, error) {
	if encoder := RegisteredBodyEncoder(mediaType); encoder != nil {
		return encoder(body)
	}
	return nil, &ParseError{
		Kind:   KindUnsupportedFormat,
		Reason: fmt.Sprintf("%s %q", prefixUnsupportedCT, mediaType),
	}
}


type BodyEncoder func(body any) ([]byte, error)

var bodyEncodersM sync.RWMutex
var bodyEncoders = map[string]BodyEncoder{
	"application/json": json.Marshal,
}


func RegisterBodyEncoder(contentType string, encoder BodyEncoder) {
	if contentType == "" {
		panic("contentType is empty")
	}
	if encoder == nil {
		panic("encoder is not defined")
	}
	bodyEncodersM.Lock()
	bodyEncoders[contentType] = encoder
	bodyEncodersM.Unlock()
}


func UnregisterBodyEncoder(contentType string) {
	if contentType == "" {
		panic("contentType is empty")
	}
	bodyEncodersM.Lock()
	delete(bodyEncoders, contentType)
	bodyEncodersM.Unlock()
}




func RegisteredBodyEncoder(contentType string) BodyEncoder {
	bodyEncodersM.RLock()
	mayBE := bodyEncoders[contentType]
	bodyEncodersM.RUnlock()
	return mayBE
}
