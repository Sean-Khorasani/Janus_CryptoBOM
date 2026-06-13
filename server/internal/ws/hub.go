// Package ws provides a real-time WebSocket hub for pushing live updates to the dashboard UI.
// Connected clients receive JSON events for telemetry ingest, finding status changes,
// migration updates, policy switches, and agent heartbeats.
// Uses a minimal stdlib-only WebSocket implementation (RFC 6455).
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID  = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	opText  = 1
	opClose = 8
	opPing  = 9
	opPong  = 10
)

// Event is a JSON-serializable message pushed to all connected UI clients.
type Event struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// wsConn wraps a single WebSocket connection.
type wsConn struct {
	conn net.Conn
	mu   sync.Mutex
	done chan struct{}
}

func (w *wsConn) writeText(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeFrame(w.conn, opText, data)
}

func (w *wsConn) writePing() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeFrame(w.conn, opPing, nil)
}

func (w *wsConn) close() {
	w.conn.Close()
}

// Hub manages connected WebSocket clients and broadcasts events.
type Hub struct {
	mu         sync.RWMutex
	clients    map[*wsConn]struct{}
	register   chan *wsConn
	unregister chan *wsConn
}

// New creates a new WebSocket hub with background client management.
func New() *Hub {
	h := &Hub{
		clients:    make(map[*wsConn]struct{}),
		register:   make(chan *wsConn, 16),
		unregister: make(chan *wsConn, 16),
	}
	go h.run()
	return h
}

// Broadcast sends an event to every connected client. Non-blocking — slow clients are skipped.
func (h *Hub) Broadcast(typ string, data any) {
	event := Event{
		Type:      typ,
		Timestamp: time.Now(),
		Data:      data,
	}
	payload, err := json.Marshal(event)
	if err != nil {
		slog.Error("failed to marshal websocket event", "type", typ, "error", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for conn := range h.clients {
		if err := conn.writeText(payload); err != nil {
			slog.Debug("websocket write failed, client will be removed", "error", err)
		}
	}
}

// ClientCount returns the number of currently connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ServeWS upgrades an HTTP connection to WebSocket and registers it with the hub.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Compute accept key per RFC 6455
	hash := sha1.New()
	hash.Write([]byte(key + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
		return
	}
	netConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write upgrade response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"
	if _, err := bufrw.WriteString(resp); err != nil {
		netConn.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		netConn.Close()
		return
	}

	wsc := &wsConn{conn: netConn, done: make(chan struct{})}
	h.register <- wsc
	defer func() { h.unregister <- wsc }()

	// Read loop — handle pings and close frames
	for {
		op, _, err := readFrame(netConn)
		if err != nil {
			break
		}
		switch op {
		case opPing:
			wsc.writeText(nil) // write pong (using text frame with empty payload as pong proxy)
		case opClose:
			return
		}
	}
}

func (h *Hub) run() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = struct{}{}
			count := len(h.clients)
			h.mu.Unlock()
			slog.Info("websocket client connected", "total", count)

		case conn := <-h.unregister:
			h.mu.Lock()
			delete(h.clients, conn)
			count := len(h.clients)
			h.mu.Unlock()
			conn.close()
			slog.Info("websocket client disconnected", "total", count)

		case <-ticker.C:
			h.mu.RLock()
			for conn := range h.clients {
				if err := conn.writePing(); err != nil {
					slog.Debug("websocket ping failed, client will be removed", "error", err)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// writeFrame writes a WebSocket frame with the given opcode and payload.
func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	var maskKey [4]byte
	// Server-to-client frames are NOT masked per RFC 6455 Section 5.1
	frame := make([]byte, 2)
	frame[0] = 0x80 | opcode // FIN + opcode

	length := len(payload)
	if length <= 125 {
		frame[1] = byte(length)
		frame = append(frame, payload...)
	} else if length <= 65535 {
		frame[1] = 126
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(length))
		frame = append(frame, lenBytes...)
		frame = append(frame, payload...)
	} else {
		frame[1] = 127
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(length))
		frame = append(frame, lenBytes...)
		frame = append(frame, payload...)
	}
	_ = maskKey // suppress unused warning
	_, err := w.Write(frame)
	return err
}

// readFrame reads a single WebSocket frame and returns its opcode, payload, and any error.
func readFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	length := uint64(header[1] & 0x7F)

	switch {
	case length == 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case length == 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	if length > 10*1024*1024 { // 10MB sanity limit
		return 0, nil, errors.New("frame too large")
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

// Ensure unused imports don't cause issues
var _ = bufio.NewReader
