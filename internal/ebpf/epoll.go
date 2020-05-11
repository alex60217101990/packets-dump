package ebpf

import (
	"io"
	"log"
	"sync"
	"syscall"
)

type Epoll struct {
	epfd        int
	descriptors map[int]io.Closer
	lock        *sync.RWMutex
}

func (p *Epoll) Init() (err error) {
	p.epfd, err = syscall.EpollCreate1(0)
	if err != nil {
		log.Printf("epoll_create1: %v\n", err)
	}
	return err
}

func (p *Epoll) Remove(fd int) error {
	err := syscall.EpollCtl(p.epfd, syscall.EPOLL_CTL_DEL, fd, nil)
	if err != nil {
		return err
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	delete(p.descriptors, fd)
	return nil
}

func (p *Epoll) Close() (err error) {
	for fd := range p.descriptors {
		err = p.Remove(fd)
		if err != nil {
			return err
		}
	}
	log.Println("epoll close")
	return syscall.Close(p.epfd)
}
