package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/watchblind/agent/internal/protocol"
	"github.com/gorilla/websocket"
)

// Connection manages a persistent WebSocket connection to the server.
// It handles reconnection with exponential backoff and message routing.
type Connection struct {
	url     string
	token   string
	agentID string
	version string

	conn   *websocket.Conn
	connMu sync.Mutex

	connected atomic.Bool
	stopCh    chan struct{}
	sendCh    chan []byte

	// retryUntil is a unix millisecond timestamp until which sends are paused.
	// Set when server sends an error with retry_after.
	retryUntil atomic.Int64

	// Callbacks
	onAck        func(batchID string)
	onPace       func(intervalMS, collectMS int)
	onConfig     func(encConfig string)
	onDisconnect func(reason string)
	onConnected  func(pace protocol.PaceConfig)
	onDEKRotated func(newEpoch int)
}

// NewConnection creates a new WebSocket connection manager.
func NewConnection(url, token, agentID, version string) *Connection {
	return &Connection{
		url:     url,
		token:   token,
		agentID: agentID,
		version: version,
		stopCh:  make(chan struct{}),
		sendCh:  make(chan []byte, 256),
	}
}

// Callbacks

func (c *Connection) OnAck(fn func(batchID string))                { c.onAck = fn }
func (c *Connection) OnPace(fn func(intervalMS, collectMS int))     { c.onPace = fn }
func (c *Connection) OnConfig(fn func(encConfig string))             { c.onConfig = fn }
func (c *Connection) OnDisconnect(fn func(reason string))           { c.onDisconnect = fn }
func (c *Connection) OnConnected(fn func(pace protocol.PaceConfig)) { c.onConnected = fn }
func (c *Connection) OnDEKRotated(fn func(newEpoch int))            { c.onDEKRotated = fn }

// IsConnected returns whether the WebSocket is currently connected.
func (c *Connection) IsConnected() bool {
	return c.connected.Load()
}

// Run starts the connection loop. It blocks until ctx is cancelled.
// Handles reconnection with exponential backoff.
func (c *Connection) Run(ctx context.Context) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		err := c.connect(ctx)
		if err != nil {
			delay := backoff(attempt)
			log.Printf("[ws] connection failed (attempt %d): %v, retrying in %v", attempt+1, err, delay)
			attempt++

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			}
			continue
		}

		// Connected — reset backoff
		attempt = 0

		// Read loop (blocks until disconnect)
		c.readLoop(ctx)

		c.connected.Store(false)
		log.Printf("[ws] disconnected, reconnecting...")
	}
}

// Send queues a message for sending. Non-blocking; drops if buffer full.
func (c *Connection) Send(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	select {
	case c.sendCh <- data:
		return nil
	default:
		return fmt.Errorf("send buffer full, message dropped")
	}
}

// SendSync sends a message and blocks until it's written to the WebSocket.
func (c *Connection) SendSync(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// Close gracefully closes the connection.
func (c *Connection) Close() error {
	close(c.stopCh)
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Connection) connect(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.token)
	header.Set("X-BW-Agent", c.agentID)
	if c.version != "" {
		header.Set("X-BW-Agent-Version", c.version)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, c.url, header)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	// Start write pump
	go c.writePump(ctx)

	c.connected.Store(true)
	return nil
}

func (c *Connection) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		c.connMu.Lock()
		conn := c.conn
		c.connMu.Unlock()
		if conn == nil {
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}

		c.handleMessage(data)
	}
}

func (c *Connection) writePump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case data := <-c.sendCh:
			// Respect server retry_after before sending
			if until := c.retryUntil.Load(); until > 0 {
				delay := time.Until(time.UnixMilli(until))
				if delay > 0 {
					log.Printf("[ws] rate limited, waiting %v before sending", delay.Truncate(time.Millisecond))
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return
					case <-c.stopCh:
						return
					}
				}
			}

			c.connMu.Lock()
			conn := c.conn
			c.connMu.Unlock()
			if conn == nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		}
	}
}

func (c *Connection) handleMessage(data []byte) {
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		log.Printf("[ws] invalid message: %v", err)
		return
	}

	switch env.Type {
	case "connected":
		var msg protocol.ConnectedMessage
		if json.Unmarshal(data, &msg) == nil && c.onConnected != nil {
			c.onConnected(msg.Pace)
		}

	case "ack":
		var msg protocol.AckMessage
		if json.Unmarshal(data, &msg) == nil && c.onAck != nil {
			c.onAck(msg.BatchID)
		}

	case "pace":
		var msg protocol.PaceMessage
		if json.Unmarshal(data, &msg) == nil && c.onPace != nil {
			c.onPace(msg.IntervalMS, msg.CollectMS)
		}

	case "config":
		var msg protocol.ConfigMessage
		if json.Unmarshal(data, &msg) == nil && c.onConfig != nil {
			c.onConfig(msg.EncConfig)
		}

	case "dek_rotated":
		var msg protocol.DEKRotatedMessage
		if json.Unmarshal(data, &msg) == nil && c.onDEKRotated != nil {
			c.onDEKRotated(msg.NewEpoch)
		}

	case "disconnect":
		var msg protocol.DisconnectMessage
		if json.Unmarshal(data, &msg) == nil && c.onDisconnect != nil {
			c.onDisconnect(msg.Reason)
		}

	case "error":
		var msg protocol.ErrorMessage
		if json.Unmarshal(data, &msg) == nil {
			log.Printf("[ws] server error: code=%s retry_after=%d", msg.Code, msg.RetryAfter)
			if msg.RetryAfter > 0 {
				until := time.Now().Add(time.Duration(msg.RetryAfter) * time.Second)
				c.retryUntil.Store(until.UnixMilli())
				log.Printf("[ws] pausing sends for %ds (until %s)", msg.RetryAfter, until.Format("15:04:05"))
			}
		}

	default:
		log.Printf("[ws] unknown message type: %s", env.Type)
	}
}

func backoff(attempt int) time.Duration {
	d := time.Duration(math.Pow(2, float64(attempt))) * time.Second
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	// Add jitter to prevent thundering herd on mass reconnects
	jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
	return d + jitter
}
