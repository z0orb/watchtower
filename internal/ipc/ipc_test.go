package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := NewServer()
	go s.Serve(l)
	s.Send(Msg{Type: "status", Status: &Status{Network: "home|192.168.1.1"}})

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	sc := bufio.NewScanner(c)
	read := func() Msg {
		t.Helper()
		if !sc.Scan() {
			t.Fatal("read:", sc.Err())
		}
		var m Msg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	if m := read(); m.Type != "status" || m.Status.Network != "home|192.168.1.1" {
		t.Fatalf("replayed status = %+v", m)
	}

	c.Write([]byte("garbage\n{\"type\":\"cmd\",\"name\":\"retrust\"}\n"))
	cmd := <-s.Cmds
	if cmd.Name != "retrust" {
		t.Fatalf("cmd = %q", cmd.Name)
	}
	cmd.Reply(errors.New("conflict"))
	if m := read(); m.Type != "result" || m.Name != "retrust" || m.Text != "conflict" {
		t.Fatalf("result = %+v", m)
	}

	s.Send(Msg{Type: "alert", Name: "arp_spoof"})
	if m := read(); m.Type != "alert" || m.Name != "arp_spoof" {
		t.Fatalf("alert = %+v", m)
	}
}

func TestSlowClientDropped(t *testing.T) {
	s := NewServer()
	out := make(chan Msg, 16)
	s.conns[out] = true
	for range 17 {
		s.Send(Msg{Type: "alert"})
	}
	if s.conns[out] {
		t.Fatal("client that fell behind is still registered")
	}
}
