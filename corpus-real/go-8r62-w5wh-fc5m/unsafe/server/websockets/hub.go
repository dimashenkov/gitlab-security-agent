
package websockets

import (
	"encoding/json"
	"sync/atomic"

	"github.com/axllent/mailpit/internal/logger"
	"github.com/gorilla/websocket"
)



type Hub struct {

	Clients map[*Client]bool


	Broadcast chan []byte


	register chan *Client


	unregister chan *Client


	clientCount atomic.Int64
}


type WebsocketNotification struct {
	Type string
	Data any
}


func NewHub() *Hub {
	return &Hub{
		Broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		Clients:    make(map[*Client]bool),
	}
}


func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			if _, ok := h.Clients[client]; !ok {
				logger.Log().Debugf("[websocket] client %s connected", client.conn.RemoteAddr().String())
				h.Clients[client] = true
				h.clientCount.Add(1)
			}
		case client := <-h.unregister:
			if _, ok := h.Clients[client]; ok {
				logger.Log().Debugf("[websocket] client %s disconnected", client.conn.RemoteAddr().String())
				delete(h.Clients, client)
				close(client.send)
				h.clientCount.Add(-1)
			}
		case message := <-h.Broadcast:
			prepared, err := websocket.NewPreparedMessage(websocket.TextMessage, message)
			if err != nil {
				logger.Log().Errorf("[websocket] error preparing message: %s", err.Error())
				continue
			}
			for client := range h.Clients {
				select {
				case client.send <- prepared:
				default:
					close(client.send)
					delete(h.Clients, client)
					h.clientCount.Add(-1)
				}
			}
		}
	}
}


func Broadcast(t string, msg any) {
	if MessageHub == nil || MessageHub.clientCount.Load() == 0 {
		return
	}

	w := WebsocketNotification{}
	w.Type = t
	w.Data = msg
	b, err := json.Marshal(w)

	if err != nil {
		logger.Log().Errorf("[websocket] broadcast received invalid data: %s", err.Error())
		return
	}

	go func() { MessageHub.Broadcast <- b }()
}


func BroadCastClientError(severity, errorType, ip, message string) {
	msg := struct {
		Level   string
		Type    string
		IP      string
		Message string
	}{
		severity,
		errorType,
		ip,
		message,
	}

	Broadcast("error", msg)
}
