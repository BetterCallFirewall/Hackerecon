package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Hub управляет одним активным соединением.
type Hub struct {
	client     *Client // Может быть nil, если нет активного клиента
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex // Мьютекс для защиты доступа к client
}

func NewHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Client представляет активное WebSocket соединение.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

type Message struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			// Если уже есть активный клиент, отключаем его.
			h.mutex.Lock()
			if h.client != nil {
				close(h.client.send)
			}
			h.client = client
			h.mutex.Unlock()
			log.Printf("WebSocket client connected")

		case client := <-h.unregister:
			h.mutex.Lock()
			// Убедимся, что отключаем того же самого клиента, который активен.
			if h.client == client {
				close(h.client.send)
				h.client = nil // Очищаем ссылку на клиента
				log.Printf("WebSocket client disconnected")
			}
			h.mutex.Unlock()

		case message := <-h.broadcast:
			h.mutex.RLock()
			// Отправляем сообщение только если клиент подключен
			if h.client != nil {
				select {
				case h.client.send <- message:
				default:
					// Если канал переполнен, считаем клиента "медленным" и отключаем.
					log.Printf("Client send channel is full. Closing connection.")
					close(h.client.send)
					h.client = nil
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// Broadcast безопасно отправляет сообщение активному клиенту.
func (h *Hub) Broadcast(data interface{}) {
	msg := Message{
		Type:      "request",
		Data:      data,
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}

	// Отправляем в канал broadcast. `Run` обработает отправку клиенту.
	// Можно добавить проверку, чтобы не нагружать канал, если клиента нет.
	h.mutex.RLock()
	clientExists := h.client != nil
	h.mutex.RUnlock()

	if clientExists {
		h.broadcast <- jsonData
	} else {
		log.Println("No active client to broadcast to, skipping message")
	}
}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}

	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		// Мы должны читать сообщения, чтобы обнаружить, когда клиент отключается
		if _, _, err := c.conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("readPump error: %v", err)
			}
			break
		}
	}
}

func (c *Client) writePump() {
	defer c.conn.Close()
	for {
		message, ok := <-c.send
		if !ok {
			// Канал `send` был закрыт хабом.
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}
		c.conn.WriteMessage(websocket.TextMessage, message)
	}
}
