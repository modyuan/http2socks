package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type addr struct {
	v string
}

func (a *addr) String() string {
	return a.v
}
func (a *addr) Set(s string) error {
	arr := strings.Split(s, ":")
	if len(arr) != 2 {
		return errors.New("Invalid parameter")
	}
	port, err := strconv.Atoi(arr[1])
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("Invalid parameter")
	}
	a.v = s
	return nil
}

type forward struct {
	forwardto string
}

func (s forward) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	hostname, port := req.URL.Hostname(), req.URL.Port()

	hij, ok := res.(http.Hijacker)
	if !ok {
		panic("http server dost not support hijacker")
		//从golnag代码看，肯定是不会失败的啦~
	}
	client, _, err := hij.Hijack()
	if err != nil {
		return
	}
	//
	server, err := net.Dial("tcp", s.forwardto)
	if err != nil {
		log.Print("Fail to link socks proxy,can't link to", s.forwardto)
		return
	}
	// client -> server
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     |  1~255   |
	// +----+----------+----------+
	server.Write([]byte("\x05\x01\x00"))

	// server -> client
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	temp := make([]byte, 24)
	_, err = io.ReadAtLeast(server, temp, 2)
	if err != nil || string(temp[:2]) != "\x05\x00" {
		log.Print("Fail to link socks proxy, proxy refuse to link by method 0x00")
	}

	// client -> server , send request
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  |   1   |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	buf := bytes.NewBuffer([]byte("\x05\x01\x00"))
	if testip := net.ParseIP(hostname); testip == nil {
		//hostname is domain
		buf.WriteByte(3)
		domainlen := len(hostname)
		buf.WriteByte(byte(domainlen))
		buf.WriteString(hostname)
	} else {
		//hostname is ipv4
		buf.WriteByte(1)
		buf.Write(testip)
	}
	if port == "" {
		port = "80"
	}
	port2, _ := strconv.Atoi(port)
	binary.Write(buf, binary.BigEndian, uint16(port2))
	buf.WriteTo(server)

	// server -> client , response
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  |   1   |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	_, err = io.ReadAtLeast(server, temp, 8)
	if err != nil || temp[1] != 0 {
		log.Fatal("socks server return error. REP =", temp[1])
		return
	}
	if req.Method == "CONNECT" {
		client.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
		//https
		go io.Copy(server, client)
		io.Copy(client, server)
	} else {
		//http
		go req.Write(server)
		io.Copy(client, server)

	}

}

func main() {
	//var myhttp, mysocks string
	var myhttp, mysocks addr
	flag.Var(&myhttp, "http", "ip:port - http proxy to listen,\n\tdefault for 127.0.0.1:8080")
	flag.Var(&mysocks, "socks", "ip:port - http proxy to listen,\n\tdefault for 127.0.0.1:1080")
	flag.Parse()

	if myhttp.v == "" {
		myhttp.v = "127.0.0.1:8080"
	}
	if mysocks.v == "" {
		mysocks.v = "127.0.0.1:1080"
	}
	log.Print("Opened simple http proxy on [", myhttp.v, "]")
	log.Print("Forwarding to socks proxy on [", mysocks.v, "]")
	forwarder := forward{mysocks.v}

	s := &http.Server{
		Addr:           myhttp.v,
		Handler:        forwarder,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.ListenAndServe()

}
