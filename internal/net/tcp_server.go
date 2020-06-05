package net

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alex60217101990/packets-dump/internal/errors"
	"github.com/alex60217101990/packets-dump/internal/logger"
	"github.com/alex60217101990/types/enums"
	"github.com/alex60217101990/types/models"
)

type TCPServer struct {
	npoll *Epoll
	// gpoll    *ants.PoolWithFunc
	workerPool *Pool
	listener   net.Listener
	servMap    sync.Map // map[models.TCPConnMeta]int
}

func NewTCPServer() *TCPServer {
	s := &TCPServer{}
	var err error
	// ants will pre-malloc the whole capacity of pool when you invoke this method
	// s.gpoll, err = ants.NewPoolWithFunc(100000, s.runTask, ants.WithPreAlloc(false))
	// if err != nil {
	// 	logger.Sugar.Error(err)
	// 	os.Exit(2)
	// }
	logger.Green.Println("🐜 goroutine pool create success!")
	s.npoll, err = MkEpoll()
	if err != nil {
		logger.Sugar.Error(err)
		os.Exit(2)
	}
	s.workerPool = newPool(1, 1000000, s.npoll)
	logger.Green.Println("🧵 connections pool create success!")
	// config := memberlist.DefaultLocalConfig()
	// config.Logger = logger.ClusterLogger
	// list, err := memberlist.Create(config)
	// if err != nil {
	// 	logger.Sugar.Error(err)
	// 	os.Exit(1)
	// }

	return s
}

func (s *TCPServer) SendSidecarMsg(key *models.TCPConnMeta, msg models.SidecarEvent) {
	if key != nil {
		fd, ok := s.servMap.Load(*key)
		if ok {
			s.npoll.Send(Event{Fd: fd.(int), Data: msg})
		}
	}
}

func (s *TCPServer) SendAll(msg models.SidecarEvent) {
	s.servMap.Range(func(k, v interface{}) bool {
		s.npoll.Send(Event{Fd: v.(int), Data: msg})
		return true
	})
}

func (s *TCPServer) GetSidecarKey(id string) (mapKey *models.TCPConnMeta) {
	s.servMap.Range(func(k, v interface{}) bool {
		if key, ok := k.(models.TCPConnMeta); ok && key.ServiceID == id {
			mapKey = &key
			return false
		}
		return true
	})
	return mapKey
}

func (s *TCPServer) Run() {
	s.workerPool.start()
	s.listen()
	s.start()
	logger.Green.Println("🖥️  TCP server start success!")
}

func (s *TCPServer) start() {
	go func() {
		for {
			connections, err := s.npoll.Wait()
			if err != nil {
				logger.Sugar.Errorf("failed to epoll wait %v", err)
				continue
			}
			for _, conn := range connections {
				if conn == nil {
					break
				}
				// s.gpoll.Invoke(conn)
				s.workerPool.addTask(conn)
			}
		}
	}()
}

func (s *TCPServer) listen() {
	err := SetLimit()
	if err != nil {
		logger.Sugar.Error(err)
		os.Exit(1)
	}
	s.listener, err = net.Listen("tcp", ":8972")
	if err != nil {
		logger.Sugar.Error(err)
		os.Exit(1)
	}
	var fd int
	go func() {
		for {
			conn, e := s.listener.Accept()
			if e != nil {
				if ne, ok := e.(net.Error); ok && ne.Temporary() {
					logger.Sugar.Warnf("accept temp err: %v", ne)
					continue
				}
				logger.Sugar.Errorf("accept err: %v", e)
				return
			}
			fd, err = s.npoll.Add(conn)
			if err != nil {
				logger.Sugar.Errorf("failed to add connection %v", err)
				conn.Close()
				continue
			}
			s.servMap.Store(models.TCPConnMeta{
				ServiceID:   "111",
				ServiceType: enums.Sidecar,
				ServiceAddr: conn.RemoteAddr().String(),
			}, fd)
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetDeadline(time.Now().Add(time.Second * 30))
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(time.Second * 7)
			}
		}
	}()
}

func (s *TCPServer) Close() {
	var err error
	s.servMap.Range(func(k, v interface{}) bool {
		err = s.npoll.RemoveByFd(v.(int))
		if err != nil && !strings.Contains(err.Error(), errors.BadFileDescriptor.Error()) {
			logger.Sugar.Errorf("failed to delete connection %v", err)
		}
		return true
	})
	// s.gpoll.Free()
	s.workerPool.Close()
	// for i := 0; i < cap(s.shutdown); i++ {
	// 	s.shutdown <- struct{}{}
	// }
	logger.Green.Println("🚫 TCP server stoped success!")
}
