// Package ipc connects the service and the tray: line-delimited JSON over a named pipe.
package ipc

import (
	"bufio"
	"encoding/json"
	"net"
	"sync"
)

// Msg is one line on the pipe. Service → tray: "status", "alert", "result". Tray → service: "cmd".
type Msg struct {
	Type   string  `json:"type"`
	Name   string  `json:"name,omitempty"` // alert kind, or command name (also echoed in its result)
	Text   string  `json:"text,omitempty"` // alert message, or command error ("" = ok)
	Status *Status `json:"status,omitempty"`
}

type Status struct {
	Network   string `json:"network"` // "" = not connected
	Adapter   string `json:"adapter"`
	Trusted   string `json:"trusted"` // pinned gateway MAC; "" = not pinned
	Npcap     bool   `json:"npcap"`
	PublicDNS bool   `json:"public_dns"` // switched to 1.1.1.1/8.8.8.8
	Link      bool   `json:"link"`
	Gateway   bool   `json:"gateway"`
	Internet  bool   `json:"internet"`
	DNS       bool   `json:"dns"`
}

// Cmd is a tray request; Reply sends its result back to that tray.
type Cmd struct {
	Name  string
	Reply func(err error)
}

// Server broadcasts to every connected tray and queues their commands on Cmds.
type Server struct {
	Cmds chan Cmd

	mu     sync.Mutex
	conns  map[chan Msg]bool
	status *Status // last sent, replayed to new trays
}

func NewServer() *Server { return &Server{Cmds: make(chan Cmd), conns: map[chan Msg]bool{}} }

// Serve accepts trays until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// Send never blocks: a tray that falls 16 messages behind is dropped.
func (s *Server) Send(m Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Status != nil {
		st := *m.Status
		s.status = &st
	}
	for out := range s.conns {
		s.push(out, m)
	}
}

func (s *Server) push(out chan Msg, m Msg) {
	select {
	case out <- m:
	default:
		delete(s.conns, out)
		close(out)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	out := make(chan Msg, 16)
	s.mu.Lock()
	s.conns[out] = true
	if s.status != nil {
		s.push(out, Msg{Type: "status", Status: s.status})
	}
	s.mu.Unlock()

	go func() {
		enc := json.NewEncoder(c) // Encode appends the newline
		for m := range out {
			if enc.Encode(m) != nil {
				break
			}
		}
		c.Close() // unblocks the reader below
	}()

	sc := bufio.NewScanner(c) // 64 KB line limit
	for sc.Scan() {
		var m Msg
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Type != "cmd" {
			continue
		}
		name := m.Name
		s.Cmds <- Cmd{Name: name, Reply: func(err error) {
			r := Msg{Type: "result", Name: name}
			if err != nil {
				r.Text = err.Error()
			}
			s.mu.Lock()
			if s.conns[out] {
				s.push(out, r)
			}
			s.mu.Unlock()
		}}
	}
	s.mu.Lock()
	if s.conns[out] {
		delete(s.conns, out)
		close(out)
	}
	s.mu.Unlock()
}
