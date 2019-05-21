package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

type Connection struct {
	*ssh.Client
	password string
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

func (c *Client) Connect() error {
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
		return ErrNoUser
	}

	password := os.Getenv("PW")
	if password == "" {
		return ErrNoPasswd
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
		return err
	}

	sshConn := &Connection{
		conn,
		password,
	}

	session, err := sshConn.NewSession()
	if err != nil {
		return err
	}

	err = session.RequestPty(term, h, w, ssh.TerminalModes{
		ssh.ECHO:          echo,     // disable echoing
		ssh.TTY_OP_ISPEED: baudRate, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: baudRate, // output speed = 14.4kbaud
	})
	if err != nil {
		return err
	}
	session.Stdin = c.WS
	session.Stdout = c.WS
	session.Stderr = c.WS

	err = session.Shell()
	if err != nil {
		return err
	}

	// Sleep for a bit and wait for the connection to begin
	time.Sleep(1000 * time.Millisecond)

	uuid, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	c.ID = uuid.String()
	c.SSH = session

	for {
	}

	return nil
}

func (c *Client) Disconnect() error {
	// close ssh tunnel
	err := c.SSH.Close()
	if err != nil {
		return err
	}

	c.WS.Write([]byte("Disconnected!"))

	// close the websocket
	err = c.WS.Close()
	if err != nil {
		return err
	}

	return nil
}

func ServeWS(ws *websocket.Conn) {
	client := &Client{
		WS: ws,
	}

	err := client.Connect()
	if err != nil {
		fmt.Println("err", err)
	}

	ClientMap[client.ID] = client

	fmt.Println("connecting", client.ID)
}
