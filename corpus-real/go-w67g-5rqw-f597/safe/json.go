



package websocket

import (
	"encoding/json"
	"io"
)




func WriteJSON(c *Conn, v interface{}) error {
	return c.WriteJSON(v)
}





func (c *Conn) WriteJSON(v interface{}) error {
	w, err := c.NextWriter(TextMessage)
	if err != nil {
		return err
	}
	err1 := json.NewEncoder(w).Encode(v)
	err2 := w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}





func ReadJSON(c *Conn, v interface{}) error {
	return c.ReadJSON(v)
}






func (c *Conn) ReadJSON(v interface{}) error {
	_, r, err := c.NextReader()
	if err != nil {
		return err
	}
	err = json.NewDecoder(r).Decode(v)
	if err == io.EOF {

		err = io.ErrUnexpectedEOF
	}
	return err
}
