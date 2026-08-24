



package websockets

import (
	"net/http"
	"time"

	"github.com/axllent/mailpit/config"
	"github.com/axllent/mailpit/internal/auth"
	"github.com/axllent/mailpit/internal/logger"
	"github.com/gorilla/websocket"
)

const (

	writeWait = 10 * time.Second


	pongWait = 60 * time.Second


	pingPeriod = (pongWait * 9) / 10
)

var (

	MessageHub *Hub
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	EnableCompression: !config.DisableHTTPCompression,
	CheckOrigin: func(_ *http.Request) bool {

		return true
	},
}


type Client struct {
	hub *Hub


	conn *websocket.Conn


	send chan *websocket.PreparedMessage
}


func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	for {
		_, _, err := c.conn.NextReader()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Log().Errorf("[websocket] error: %v", err.Error())
			}
			break
		}
	}
}






func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {

				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WritePreparedMessage(message); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}


func ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	if auth.UICredentials != nil {
		user, pass, ok := r.BasicAuth()

		if !ok {
			basicAuthResponse(w)
			return
		}

		if !auth.UICredentials.Match(user, pass) {
			basicAuthResponse(w)
			return
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Log().Errorf("[websocket] %s", err.Error())
		return
	}

	client := &Client{hub: hub, conn: conn, send: make(chan *websocket.PreparedMessage, 256)}
	client.hub.register <- client


	go client.readPump()
	go client.writePump()
}


func basicAuthResponse(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Login"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("Unauthorized.\n"))
}
