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

// sendItem wraps raw message bytes with a rate-limit category so the
// write pump can skip messages whose category is currently throttled.
type sendItem struct {
	data     []byte
	category string // "live", "batch", "wal", "other"
}

const (
	defaultPingInterval = 15 * time.Second
	defaultReadDeadline = 45 * time.Second
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
	sendCh    chan sendItem

	pingInterval time.Duration
	readDeadline time.Duration

	// Per-category retryUntil — unix millisecond timestamp until which
	// sends of that category are paused. Keyed by category string.
	categoryRetry sync.Map // map[string]*atomic.Int64

	// lastFailLog tracks when we last emitted a connection-failure log line
	// so we can throttle repeated failure messages to once per minute.
	lastFailLog time.Time

	// Callbacks
	onAck        func(batchID string)
	onPace       func(intervalMS, collectMS int)
	onConfig     func(encConfig string)
	onDisconnect func(reason string)
	onConnected  func(pace protocol.PaceConfig)
	onDEKRotated func(newEpoch int)
}

func (c *Connection) SetPingInterval(d time.Duration) { c.pingInterval = d }
func (c *Connection) SetReadDeadline(d time.Duration) { c.readDeadline = d }

// msgCategory maps a message type to a rate-limit category.
func msgCategory(msgType string) string {
	switch msgType {
	case "live", "live_proc":
		return "live"
	case "batch", "flush", "batch_proc":
		return "batch"
	case "wal_sync":
		return "wal"
	default:
		return "other"
	}
}

// NewConnection creates a new WebSocket connection manager.
func NewConnection(url, token, agentID, version string) *Connection {
	return &Connection{
		url:          url,
		token:        token,
		agentID:      agentID,
		version:      version,
		stopCh:       make(chan struct{}),
		sendCh:       make(chan sendItem, 256),
		pingInterval: defaultPingInterval,
		readDeadline: defaultReadDeadline,
	}
}

// getRetryUntil returns the atomic retry timestamp for a category.
func (c *Connection) getRetryUntil(category string) *atomic.Int64 {
	val, _ := c.categoryRetry.LoadOrStore(category, &atomic.Int64{})
	return val.(*atomic.Int64)
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
			now := time.Now()
			if attempt == 0 || now.Sub(c.lastFailLog) >= time.Minute {
				log.Printf("[ws] connection failed (attempt %d): %v, retrying in %v", attempt+1, err, delay)
				c.lastFailLog = now
			}
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
		if !c.lastFailLog.IsZero() {
			log.Printf("[ws] reconnected")
			c.lastFailLog = time.Time{}
		}
		attempt = 0

		// Read loop (blocks until disconnect)
		c.readLoop(ctx)

		c.connected.Store(false)
		c.drainSendCh()
		log.Printf("[ws] disconnected, reconnecting...")

		// Apply backoff(0) before reconnect so IsConnected()==false is
		// observable for at least the backoff window (1s + jitter).
		delay := backoff(0)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		}
	}
}

// Send queues a message for sending. Non-blocking; drops if buffer full.
func (c *Connection) Send(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	category := extractCategory(data)
	select {
	case c.sendCh <- sendItem{data: data, category: category}:
		return nil
	default:
		return fmt.Errorf("send buffer full, message dropped")
	}
}

// SendSync sends a message and blocks until it's written to the WebSocket.
// Routes through sendCh to avoid concurrent writes with writePump.
func (c *Connection) SendSync(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	category := extractCategory(data)
	select {
	case c.sendCh <- sendItem{data: data, category: category}:
		return nil
	case <-c.stopCh:
		return fmt.Errorf("connection closed")
	}
}

// extractCategory peeks at the "type" field in a JSON message to determine its rate-limit category.
func extractCategory(data []byte) string {
	var env struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &env) == nil {
		return msgCategory(env.Type)
	}
	return "other"
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

	// Set initial read deadline and refresh it on every pong received.
	conn.SetReadDeadline(time.Now().Add(c.readDeadline))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(c.readDeadline))
	})

	// Start write pump and ping loop
	go c.writePump(ctx)
	go c.pingLoop(ctx, conn)

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

		conn.SetReadDeadline(time.Now().Add(c.readDeadline))
		c.handleMessage(data)
	}
}

func (c *Connection) pingLoop(ctx context.Context, conn *websocket.Conn) {
	if c.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(c.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-t.C:
			c.connMu.Lock()
			cur := c.conn
			c.connMu.Unlock()
			if cur != conn {
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			if err := cur.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				return
			}
		}
	}
}

func (c *Connection) writePump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case item := <-c.sendCh:
			// Check per-category rate limit
			retry := c.getRetryUntil(item.category)
			if until := retry.Load(); until > 0 {
				delay := time.Until(time.UnixMilli(until))
				if delay > 0 {
					// Drop the message — don't block other categories.
					// The scheduler/WAL will retry later.
					log.Printf("[ws] %s rate-limited for %v, dropping message", item.category, delay.Truncate(time.Millisecond))
					continue
				}
			}

			c.connMu.Lock()
			if c.conn == nil {
				c.connMu.Unlock()
				return
			}
			err := c.conn.WriteMessage(websocket.TextMessage, item.data)
			c.connMu.Unlock()
			if err != nil {
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
		if json.Unmarshal(data, &msg) == nil {
			c.connected.Store(true)
			if c.onConnected != nil {
				c.onConnected(msg.Pace)
			}
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
			log.Printf("[ws] server error: code=%s category=%s retry_after=%d", msg.Code, msg.Category, msg.RetryAfter)
			if msg.Code == "RATE_LIMITED" {
				waitSec := msg.RetryAfter
				if waitSec <= 0 {
					waitSec = 10
				}
				cat := msg.Category
				if cat == "" {
					cat = "other" // fallback for old servers without category
				}
				until := time.Now().Add(time.Duration(waitSec) * time.Second)
				c.getRetryUntil(cat).Store(until.UnixMilli())
				log.Printf("[ws] %s rate limited, pausing for %ds (until %s)", cat, waitSec, until.Format("15:04:05"))
			} else if msg.RetryAfter > 0 {
				// Non-rate-limit error with retry_after — apply to all categories
				until := time.Now().Add(time.Duration(msg.RetryAfter) * time.Second)
				for _, cat := range []string{"live", "batch", "wal", "other"} {
					c.getRetryUntil(cat).Store(until.UnixMilli())
				}
				log.Printf("[ws] pausing all sends for %ds (until %s)", msg.RetryAfter, until.Format("15:04:05"))
			}
		}

	default:
		log.Printf("[ws] unknown message type: %s", env.Type)
	}
}

// drainSendCh empties the outgoing send channel non-blockingly. Called after
// a disconnect so that stale messages (which are covered by WAL replay on
// reconnect) don't produce duplicate sends.
func (c *Connection) drainSendCh() {
	for {
		select {
		case <-c.sendCh:
		default:
			return
		}
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
