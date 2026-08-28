



package websocket

import (
	"io"
	"strings"
)




func JoinMessages(c *Conn, term string) io.Reader {
	return &joinReader{c: c, term: term}
}

type joinReader struct {
	c    *Conn
	term string
	r    io.Reader
}

func (r *joinReader) Read(p []byte) (int, error) {
	if r.r == nil {
		var err error
		_, r.r, err = r.c.NextReader()
		if err != nil {
			return 0, err
		}
		if r.term != "" {
			r.r = io.MultiReader(r.r, strings.NewReader(r.term))
		}
	}
	n, err := r.r.Read(p)
	if err == io.EOF {
		err = nil
		r.r = nil
	}
	return n, err
}
