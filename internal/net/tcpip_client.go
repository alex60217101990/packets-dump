package net

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/alex60217101990/packets-dump/internal/errors"
	"github.com/alex60217101990/packets-dump/internal/logger"
	"github.com/alex60217101990/types/enums"
)

type connMetaKey struct {
	addr  string
	proto enums.PortKeyProtocol
}

type TCPIPClient struct {
	npoll      *Epoll
	workerPool *Pool
	connMap    sync.Map
}

func NewTCPIPClient() *TCPIPClient {
	var err error
	c := &TCPIPClient{}
	c.workerPool = newPool(10, 1000000, c.npoll)
	logger.Green.Println("🐜 goroutine pool create success!")
	c.npoll, err = MkEpoll()
	if err != nil {
		logger.Sugar.Error(err)
		os.Exit(int(syscall.SIGKILL))
	}
	logger.Green.Println("🌐 connections pool create success!")
	return c
}

func (c *TCPIPClient) AddClient(ip string, port uint16, protocol enums.PortKeyProtocol) (err error) {
	var (
		conn net.Conn
		fd   int
	)
	conn, err = net.Dial(protocol.String(), fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}
	fd, err = c.npoll.Add(conn)
	if err != nil {
		conn.Close()
		return err
	}
	c.connMap.Store(fmt.Sprintf("%s:%d", ip, port), fd)
	logger.Sugar.Infof("add new connection: [%s] and TCP/IP client: [%s]", conn.RemoteAddr().String(), protocol.String())
	return err
}

func (c *TCPIPClient) DelClient(ip string, port uint16) (err error) {
	defer func() {
		if err != nil {
			logger.Sugar.Infof("client: [%s:%d] was delete success", ip, port)
		}
	}()
	if fd, ok := c.connMap.Load(fmt.Sprintf("%s:%d", ip, port)); ok {
		err = c.npoll.RemoveByFd(fd.(int))
		if err == nil {
			c.connMap.Delete(fmt.Sprintf("%s:%d", ip, port))
		}
		return err
	}
	err = fmt.Errorf("can't find client by key: [%s:%d]", ip, port)
	return err
}

func (c *TCPIPClient) SendSidecarMsg(addr string, msg interface{}) {
	fd, ok := c.connMap.Load(addr)
	if ok {
		c.npoll.Send(Event{Fd: fd.(int), Data: msg})
	}
}

func (c *TCPIPClient) Run() {
	c.workerPool.start()
	c.start()
}

func (c *TCPIPClient) start() {
	go func() {
		var (
			err         error
			connections []net.Conn
		)
		for {
			connections, err = c.npoll.Wait()
			if err != nil {
				logger.Sugar.Errorf("failed to epoll wait %v", err)
				continue
			}
			for _, tcpConn := range connections {
				if tcpConn == nil {
					break
				}
				c.workerPool.addTask(tcpConn)
			}
		}
	}()
}

func (c *TCPIPClient) Close() {
	c.workerPool.Close()
	var err error
	c.connMap.Range(func(k, v interface{}) bool {
		err = c.npoll.RemoveByFd(v.(int))
		if err != nil && !strings.Contains(err.Error(), errors.BadFileDescriptor.Error()) {
			logger.Sugar.Errorf("failed to delete connection %v", err)
		}
		return true
	})
	logger.Green.Println("🚩 TCP/IP client stoped success!")
}
