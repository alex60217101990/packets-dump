package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/alex60217101990/packets-dump/internal/logger"
	network "github.com/alex60217101990/packets-dump/internal/net"
	"github.com/alex60217101990/types/enums"
	"github.com/alex60217101990/types/models"
)

// import (
// 	"flag"
// 	"fmt"
// 	"log"
// 	"math/rand"
// 	"net"
// 	"os"
// 	"os/signal"
// 	"time"

// 	"github.com/alex60217101990/packets-dump/internal/logger"
// 	network "github.com/alex60217101990/packets-dump/internal/net"
// 	"github.com/alex60217101990/types/enums"
// 	"github.com/alex60217101990/types/models"
// )

// var (
// 	ip          = flag.String("ip", "127.0.0.1", "server IP")
// 	connections = flag.Int("conn", 1, "number of tcp connections")
// 	epoller     *network.Epoll
// )

// type customConn struct {
// 	fd   int
// 	conn net.Conn
// }

// var (
// 	testMsg = []models.SidecarEvent{
// 		&models.MACBlacklistEvent{
// 			MAC:    "00:00:5e:00:53:01",
// 			Action: enums.AddAction,
// 		},
// 		&models.IPBlacklistEvent{
// 			IP:     "127.0.0.1",
// 			Type:   enums.IPv4,
// 			Action: enums.AddAction,
// 		},
// 		&models.PortBlacklistEvent{
// 			Action: enums.AddAction,
// 			Port: models.PortKey{
// 				Type:  enums.DestinationPort,
// 				Proto: enums.TCP,
// 				Port:  5555,
// 			},
// 		},
// 		&models.MACBanEvent{
// 			MAC:      "00:00:5e:00:53:01",
// 			Duration: time.Second * 20,
// 		},
// 		&models.IPBanEvent{
// 			IP:       "127.0.0.1",
// 			Type:     enums.IPv4,
// 			Duration: time.Second * 70,
// 		},
// 		&models.PortBanEvent{
// 			Port: models.PortKey{
// 				Type:  enums.DestinationPort,
// 				Proto: enums.TCP,
// 				Port:  4227,
// 			},
// 			Duration: time.Second * 30,
// 		},
// 	}
// )

// func main() {
// 	flag.Parse()
// 	logger.InitLogger()
// 	defer logger.Close()
// 	rand.Seed(time.Now().Unix())
// 	var err error
// 	epoller, err = network.MkEpoll()
// 	if err != nil {
// 		panic(err)
// 	}

// 	addr := *ip + ":8972"
// 	logger.Cyan.Printf("🕸️ TCP client: [%s] start success !\n", addr)

// 	conns := make(map[int]customConn, *connections)
// 	for i := 0; i < *connections; i++ {
// 		c, err := net.Dial("tcp", addr)
// 		if err != nil {
// 			fmt.Println("failed to connect", i, err)
// 			i--
// 			continue
// 		}
// 		d, err := epoller.Add(c)
// 		if err != nil {
// 			log.Printf("failed to add connection %v", err)
// 			c.Close()
// 			continue
// 		}
// 		conns[i] = customConn{
// 			fd:   d,
// 			conn: c,
// 		}
// 	}

// 	defer func() {
// 		for _, conn := range conns {
// 			epoller.Remove(conn.conn)
// 			conn.conn.Close()
// 		}
// 	}()

// 	// Add CTRL+C handler
// 	ctrlC := make(chan os.Signal, 1)
// 	signal.Notify(ctrlC, os.Interrupt)

// 	go func() {
// 		intervalDump := time.Duration(100) * time.Second
// 		tickerDump := time.NewTicker(intervalDump)
// 		defer tickerDump.Stop()
// 		for {
// 			select {
// 			case <-tickerDump.C:
// 				randEvent := testMsg[rand.Intn(len(testMsg))]
// 				fmt.Println(randEvent)
// 				randConn := conns[rand.Intn(len(conns))]
// 				epoller.Send(network.Event{
// 					Fd:   randConn.fd,
// 					Data: randEvent,
// 				})
// 			}
// 		}
// 	}()

// 	// Wait until Ctrl+C pressed
// 	<-ctrlC
// 	// Stop perf events and print summary
// 	logger.Red.Printf("🕸️ TCP client: [%s] stoped success !\n", addr)
// }

var (
	ip          = flag.String("ip", "127.0.0.1", "server IP")
	connections = flag.Int("conn", 1, "number of tcp connections")
	epoller     *network.Epoll
)

type customConn struct {
	fd   int
	conn net.Conn
}

var (
	testMsg = []models.SidecarEvent{
		&models.MACBlacklistEvent{
			MAC:    "00:00:5e:00:53:01",
			Action: enums.AddAction,
		},
		&models.IPBlacklistEvent{
			IP:     "127.0.0.1",
			Type:   enums.IPv4,
			Action: enums.AddAction,
		},
		&models.PortBlacklistEvent{
			Action: enums.AddAction,
			Port: models.PortKey{
				Type:  enums.DestinationPort,
				Proto: enums.TCP,
				Port:  5555,
			},
		},
		&models.MACBanEvent{
			MAC:      "00:00:5e:00:53:01",
			Duration: time.Second * 20,
		},
		&models.IPBanEvent{
			IP:       "127.0.0.1",
			Type:     enums.IPv4,
			Duration: time.Second * 70,
		},
		&models.PortBanEvent{
			Port: models.PortKey{
				Type:  enums.DestinationPort,
				Proto: enums.TCP,
				Port:  4227,
			},
			Duration: time.Second * 30,
		},
	}
)

func main() {
	flag.Parse()
	logger.InitLogger()
	defer logger.Close()

	var err error

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	clients := network.NewTCPIPClient()
	err = clients.AddClient(*ip, 8972, enums.TCP)
	if err != nil {
		logger.Sugar.Error(err)
		return
	}
	defer clients.Close()
	clients.Run()

	// Wait until Ctrl+C pressed
	<-ctrlC
	// Stop perf events and print summary
	logger.Red.Println("🕸️ TCP clients stoped success !\n")
}
