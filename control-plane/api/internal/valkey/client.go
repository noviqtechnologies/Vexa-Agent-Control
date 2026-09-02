package valkey

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNil                = errors.New("valkey: nil returned")
	ErrClosed             = errors.New("valkey: client closed")
	ErrBudgetCapExceeded  = errors.New("valkey: monthly budget microcents exceeded")
)

// Client interface for Valkey caching and distributed rate-limiting/spend operations.
type Client interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
	IncrBy(ctx context.Context, key string, delta int64) (int64, error)
	ReserveSpend(ctx context.Context, keyID string, deltaMicrocents, maxMicrocents int64) (int64, error)
	Close() error
}

// ValkeyClient connects to a Valkey instance using native RESP2 protocol.
type ValkeyClient struct {
	addr     string
	password string
	pool     chan net.Conn
	mu       sync.Mutex
	closed   bool
}

// NewClient initializes a Valkey connection pool from environment or defaults.
func NewClient() (Client, error) {
	valkeyURL := os.Getenv("VALKEY_URL")
	if valkeyURL == "" {
		valkeyURL = os.Getenv("REDIS_URL")
	}
	if valkeyURL == "" {
		valkeyURL = "127.0.0.1:6379"
	}

	// Clean up URL prefixes if provided
	addr := strings.TrimPrefix(valkeyURL, "redis://")
	addr = strings.TrimPrefix(addr, "valkey://")

	var password string
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		userInfo := parts[0]
		addr = parts[1]
		if strings.Contains(userInfo, ":") {
			password = strings.SplitN(userInfo, ":", 2)[1]
		} else {
			password = userInfo
		}
	}

	c := &ValkeyClient{
		addr:     addr,
		password: password,
		pool:     make(chan net.Conn, 32),
	}

	// Try a test connection; if unreachable, return fallback in-memory cache
	testConn, err := c.getConn(context.Background())
	if err != nil {
		// Degrade to fast thread-safe in-memory cache for standalone local execution
		return NewInMemoryClient(), nil
	}
	c.putConn(testConn)

	return c, nil
}

func (c *ValkeyClient) getConn(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	c.mu.Unlock()

	select {
	case conn := <-c.pool:
		return conn, nil
	default:
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", c.addr)
		if err != nil {
			return nil, err
		}
		if c.password != "" {
			if err := c.auth(conn); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
}

func (c *ValkeyClient) putConn(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		if conn != nil {
			conn.Close()
		}
		return
	}

	select {
	case c.pool <- conn:
	default:
		if conn != nil {
			conn.Close()
		}
	}
}

func (c *ValkeyClient) auth(conn net.Conn) error {
	cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(c.password), c.password)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("auth error: %s", line)
	}
	return nil
}

func (c *ValkeyClient) Get(ctx context.Context, key string) (string, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return "", err
	}
	defer c.putConn(conn)

	cmd := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(line, "$-1") {
		return "", ErrNil
	}
	if strings.HasPrefix(line, "$") {
		lengthStr := strings.TrimSpace(line[1:])
		length, _ := strconv.Atoi(lengthStr)
		buf := make([]byte, length+2)
		if _, err := bufio.NewReader(reader).Read(buf); err != nil {
			return "", err
		}
		return string(buf[:length]), nil
	}
	return "", fmt.Errorf("unexpected response: %s", line)
}

func (c *ValkeyClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	conn, err := c.getConn(ctx)
	if err != nil {
		return err
	}
	defer c.putConn(conn)

	var cmd string
	if ttl > 0 {
		secs := int(ttl.Seconds())
		cmd = fmt.Sprintf("*5\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n$2\r\nEX\r\n$%d\r\n%d\r\n",
			len(key), key, len(value), value, len(strconv.Itoa(secs)), secs)
	} else {
		cmd = fmt.Sprintf("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(key), key, len(value), value)
	}

	if _, err := conn.Write([]byte(cmd)); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("set error: %s", line)
	}
	return nil
}

func (c *ValkeyClient) Del(ctx context.Context, key string) error {
	conn, err := c.getConn(ctx)
	if err != nil {
		return err
	}
	defer c.putConn(conn)

	cmd := fmt.Sprintf("*2\r\n$3\r\nDEL\r\n$%d\r\n%s\r\n", len(key), key)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	return err
}

func (c *ValkeyClient) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return 0, err
	}
	defer c.putConn(conn)

	deltaStr := strconv.FormatInt(delta, 10)
	cmd := fmt.Sprintf("*3\r\n$6\r\nINCRBY\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(key), key, len(deltaStr), deltaStr)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	if strings.HasPrefix(line, ":") {
		valStr := strings.TrimSpace(line[1:])
		return strconv.ParseInt(valStr, 10, 64)
	}
	return 0, fmt.Errorf("incrby error: %s", line)
}

func (c *ValkeyClient) ReserveSpend(ctx context.Context, keyID string, deltaMicrocents, maxMicrocents int64) (int64, error) {
	// Atomic reservation check
	spendKey := fmt.Sprintf("vk_spend:%s", keyID)
	current, err := c.IncrBy(ctx, spendKey, deltaMicrocents)
	if err != nil {
		return 0, err
	}

	if maxMicrocents > 0 && current > maxMicrocents {
		// Revert delta and return error
		_, _ = c.IncrBy(ctx, spendKey, -deltaMicrocents)
		return current, ErrBudgetCapExceeded
	}

	return current, nil
}

func (c *ValkeyClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	close(c.pool)
	for conn := range c.pool {
		if conn != nil {
			conn.Close()
		}
	}
	return nil
}

// InMemoryClient provides a thread-safe fallback cache when no Valkey server is present.
type InMemoryClient struct {
	mu     sync.RWMutex
	store  map[string]string
	spends map[string]int64
}

func NewInMemoryClient() *InMemoryClient {
	return &InMemoryClient{
		store:  make(map[string]string),
		spends: make(map[string]int64),
	}
}

func (m *InMemoryClient) Get(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.store[key]
	if !ok {
		return "", ErrNil
	}
	return val, nil
}

func (m *InMemoryClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = value
	return nil
}

func (m *InMemoryClient) Del(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, key)
	return nil
}

func (m *InMemoryClient) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spends[key] += delta
	return m.spends[key], nil
}

func (m *InMemoryClient) ReserveSpend(ctx context.Context, keyID string, deltaMicrocents, maxMicrocents int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spendKey := fmt.Sprintf("vk_spend:%s", keyID)
	current := m.spends[spendKey] + deltaMicrocents

	if maxMicrocents > 0 && current > maxMicrocents {
		return m.spends[spendKey], ErrBudgetCapExceeded
	}

	m.spends[spendKey] = current
	return current, nil
}

func (m *InMemoryClient) Close() error {
	return nil
}
