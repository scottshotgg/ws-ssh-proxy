package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"gitlab.com/scottshotgg/ws-ssh-proxy/cmd"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

type Connection struct {
	*ssh.Client
	password string
}

type disconnectReq struct {
	ID string
}

func disconnect(w http.ResponseWriter, r *http.Request) {
	defer func() {
		err := r.Body.Close()
		if err != nil {
			fmt.Println("err", err)
		}
	}()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("err", err)
		w.WriteHeader(500)
		w.Write([]byte("Not disconnected: " + err.Error()))
	}

	var dr disconnectReq
	err = json.Unmarshal(body, &dr)
	if err != nil {
		fmt.Println("err", err)
		w.WriteHeader(500)
		w.Write([]byte("Not disconnected: " + err.Error()))
	}

	client := cmd.ClientMap[dr.ID]
	if client == nil {
		w.WriteHeader(404)
		w.Write([]byte("Client not found"))
	}

	fmt.Println("disconnecting", dr.ID)

	err = client.Disconnect()
	if err != nil {
		fmt.Println("err", err)
		w.WriteHeader(500)
		w.Write([]byte("Not disconnected: " + err.Error()))
	}

	w.Write([]byte("Disconnected"))
}

func main() {
	// something()
	connString := "localhost:8080"

	fmt.Println("listening:", connString)

	http.Handle("/connect", websocket.Handler(cmd.ServeWS))
	http.HandleFunc("/disconnect", disconnect)

	err := http.ListenAndServe(connString, nil)
	if err != nil {
		fmt.Println("err", err)
		os.Exit(9)
	}
}

const (
	echo        = 0
	h, w        = 80, 40
	term        = "xterm"
	connType    = "tcp"
	defaultIP   = "localhost"
	defaultPort = "22"
	baudRate    = 14400
)

type Client struct {
	ID  string
	SSH *ssh.Session
	WS  *websocket.Conn
}

var (
	hostCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }
	ClientMap    = map[string]*Client{}

	ErrNoPasswd = errors.Errorf("You must set the `PW` env variable to the desired password")
	ErrNoUser   = errors.Errorf("You must set the `UN` env variable to the desired username")
)

func something() {
	ip := os.Getenv("IP")
	if ip == "" {
		ip = defaultIP
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	username := os.Getenv("UN")
	if username == "" {
		fmt.Println("err", username)
	}

	password := os.Getenv("PW")
	if password == "" {
		fmt.Println("err", password)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostCallback,
	}

	conn, err := ssh.Dial(connType, ip+":"+port, config)
	if err != nil {
		fmt.Println("err", err)
	}

	sshConn := &Connection{
		conn,
		password,
	}

	session, err := sshConn.NewSession()
	if err != nil {
		fmt.Println("err", err)
	}

	err = session.RequestPty(term, h, w, ssh.TerminalModes{
		ssh.ECHO:          echo,     // disable echoing
		ssh.TTY_OP_ISPEED: baudRate, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: baudRate, // output speed = 14.4kbaud
	})
	if err != nil {
		fmt.Println("err", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout

	// session.Stdin = c.WS
	// session.Stdout = c.WS
	// session.Stderr = c.WS

	err = session.Shell()
	if err != nil {
		fmt.Println("err", err)
	}

	for {
	}
}
