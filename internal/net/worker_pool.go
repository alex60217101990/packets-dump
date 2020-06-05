package net

import (
	"encoding/gob"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/alex60217101990/packets-dump/internal/errors"
	"github.com/alex60217101990/packets-dump/internal/logger"
	"github.com/alex60217101990/types/models"
)

type Pool struct {
	workers   int
	maxTasks  int
	epoller   *Epoll
	taskQueue chan net.Conn

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

func newPool(w int, t int, epoll *Epoll) *Pool {
	return &Pool{
		workers:   w,
		maxTasks:  t,
		epoller:   epoll,
		taskQueue: make(chan net.Conn, t),
		done:      make(chan struct{}),
	}
}

func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	close(p.done)
	close(p.taskQueue)
	p.mu.Unlock()
}

func (p *Pool) addTask(conn net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	p.taskQueue <- conn
}

func (p *Pool) start() {
	for i := 0; i < p.workers; i++ {
		go p.startWorker()
	}
}

func (p *Pool) startWorker() {
	for {
		select {
		case <-p.done:
			return
		case conn := <-p.taskQueue:
			if conn != nil {
				p.handleConn(conn)
			}
		}
	}
}

func (p *Pool) handleConn(tcpConn net.Conn) {
	var (
		get models.SidecarEvent
		err error
	)
	defer func() {
		if r := recover(); r != nil {
			logger.Sugar.Error(r.(error))
		}
		tcpConn.SetDeadline(time.Now().Add(time.Second * 30))
	}()
	err = gob.NewDecoder(tcpConn).Decode(&get)
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			if _, err := p.epoller.Remove(tcpConn); err != nil && !strings.Contains(err.Error(), errors.BadFileDescriptor.Error()) {
				logger.Sugar.Errorf("failed to remove %v\n", err)
			}
			tcpConn.Close()
		} else if strings.Contains(err.Error(), "use of closed network connection") ||
			strings.Contains(err.Error(), "broken pipe") {
			if _, err := p.epoller.Remove(tcpConn); err != nil && !strings.Contains(err.Error(), errors.BadFileDescriptor.Error()) {
				logger.Sugar.Errorf("failed to remove %v", err)
			}
			tcpConn.Close()
		} else {
			logger.Sugar.Error(err)
		}
		return
	}
	if get == nil {
		return
	}
	iface := get.GetValue()
	switch val := iface.(type) {
	case models.MACBlacklistEvent:
		logger.Magenta.Println(val)
		// TODO: some data work...
	case models.IPBlacklistEvent:
		logger.Magenta.Println(val)
		// TODO: some data work...
	case models.PortBlacklistEvent:
		logger.Magenta.Println(val)
		// TODO: some data work...
	case models.MACBanEvent:
		logger.Magenta.Println(val)
		// TODO: some data work...
	case models.IPBanEvent:
		logger.Magenta.Println(val)
		// TODO: some data work...
	case models.PortBanEvent:
		logger.Magenta.Println(val)
		// TODO: some data work...
	default:
		logger.Red.Println("invalid data decode")
	}
	return
}
