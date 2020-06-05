package net

import (
	"encoding/gob"
	"net"
	"reflect"
	"sync"
	"syscall"

	"github.com/alex60217101990/packets-dump/internal/errors"
	"github.com/alex60217101990/packets-dump/internal/logger"
	"golang.org/x/sys/unix"
)

type Event struct {
	Fd   int
	Data interface{}
}

type Epoll struct {
	fd          int
	connections map[int]net.Conn
	lock        *sync.RWMutex
}

func MkEpoll() (*Epoll, error) {
	fd, err := unix.EpollCreate1(0)
	if err != nil {
		return nil, err
	}
	return &Epoll{
		fd:          fd,
		lock:        &sync.RWMutex{},
		connections: make(map[int]net.Conn),
	}, nil
}

func (e *Epoll) Add(conn net.Conn) (int, error) {
	// Extract file descriptor associated with the connection
	fd := socketFD(conn)
	err := unix.EpollCtl(e.fd, syscall.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.POLLIN | unix.POLLHUP, Fd: int32(fd)})
	if err != nil {
		return fd, err
	}
	e.lock.Lock()
	defer func() {
		e.lock.Unlock()
		logger.Cyan.Printf("📡 connection: [%v] connect and add to epoll\n", conn.RemoteAddr().String())
	}()
	e.connections[fd] = conn
	if len(e.connections) > 0 && len(e.connections)%100 == 0 {
		logger.Magenta.Printf("total number of connections: %v", len(e.connections))
	}
	return fd, nil
}

func (e *Epoll) Remove(conn net.Conn) (int, error) {
	fd := socketFD(conn)
	if fd > 0 {
		err := unix.EpollCtl(e.fd, syscall.EPOLL_CTL_DEL, fd, nil)
		if err != nil {
			return fd, err
		}
		e.lock.Lock()
		defer func() {
			e.lock.Unlock()
			logger.Red.Printf("📡 connection: [%v] close and remove from epoll\n", conn.RemoteAddr().String())
			conn.Close()
		}()
		delete(e.connections, fd)
		if len(e.connections) > 0 && len(e.connections)%100 == 0 {
			logger.Magenta.Printf("total number of connections: %v\n", len(e.connections))
		}
	}

	return fd, nil
}

func (e *Epoll) RemoveByFd(fd int) error {
	if fd > 0 {
		err := unix.EpollCtl(e.fd, syscall.EPOLL_CTL_DEL, fd, nil)
		if err != nil {
			return err
		}
		e.lock.Lock()
		defer e.lock.Unlock()
		err = e.connections[fd].Close()
		delete(e.connections, fd)
		if len(e.connections)%100 == 0 {
			logger.Magenta.Printf("total number of connections: %v\n", len(e.connections))
		}
		return err
	}
	return errors.BadFileDescriptor
}

func (e *Epoll) Wait() ([]net.Conn, error) {
	events := make([]unix.EpollEvent, 100)
retry:
	n, err := unix.EpollWait(e.fd, events, 100)
	if err != nil {
		if err == unix.EINTR {
			goto retry
		}
		return nil, err
	}
	e.lock.RLock()
	defer e.lock.RUnlock()
	var connections []net.Conn
	for i := 0; i < n; i++ {
		conn := e.connections[int(events[i].Fd)]
		connections = append(connections, conn)
	}
	return connections, nil
}

func socketFD(conn net.Conn) int {
	//tls := reflect.TypeOf(conn.UnderlyingConn()) == reflect.TypeOf(&tls.Conn{})
	// Extract the file descriptor associated with the connection
	//connVal := reflect.Indirect(reflect.ValueOf(conn)).FieldByName("conn").Elem()
	tcpConn := reflect.Indirect(reflect.ValueOf(conn)).FieldByName("conn")
	//if tls {
	//	tcpConn = reflect.Indirect(tcpConn.Elem())
	//}
	fdVal := tcpConn.FieldByName("fd")
	pfdVal := reflect.Indirect(fdVal).FieldByName("pfd")
	// logger.Cyan.Println(int(pfdVal.FieldByName("Sysfd").Int()))
	return int(pfdVal.FieldByName("Sysfd").Int())
}

func (e *Epoll) Send(ev Event) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	if conn, ok := e.connections[ev.Fd]; ok {
		return gob.NewEncoder(conn).Encode(&ev.Data)
	}
	return nil
}
