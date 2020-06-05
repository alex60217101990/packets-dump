package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"time"

	"github.com/alex60217101990/packets-dump/internal/logger"
	"github.com/alex60217101990/packets-dump/internal/net"
	"github.com/alex60217101990/types/enums"
	"github.com/alex60217101990/types/models"
)

// import (
// 	"os"
// 	"os/signal"

// 	"github.com/alex60217101990/packets-dump/internal/logger"
// 	"github.com/alex60217101990/packets-dump/internal/net"
// )

// func main() {
// 	logger.InitLogger()
// 	serv := net.NewTCPServer()
// 	serv.Run()
// 	defer func() {
// 		serv.Close()
// 		logger.Close()
// 	}()
// 	// Add CTRL+C handler
// 	ctrlC := make(chan os.Signal, 1)
// 	signal.Notify(ctrlC, os.Interrupt)

// 	// Wait until Ctrl+C pressed
// 	<-ctrlC
// }

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
	logger.InitLogger()
	rand.Seed(time.Now().Unix())
	serv := net.NewTCPServer()
	serv.Run()
	defer func() {
		serv.Close()
		logger.Close()
	}()
	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	go func() {
		intervalDump := time.Duration(1) * time.Second
		tickerDump := time.NewTicker(intervalDump)
		defer tickerDump.Stop()
		for {
			select {
			case <-tickerDump.C:
				randEvent := testMsg[rand.Intn(len(testMsg))]
				fmt.Println(randEvent)
				// key := serv.GetSidecarKey("111")
				// if key != nil {
				// 	serv.SendSidecarMsg(key, randEvent)
				// }
				serv.SendAll(randEvent)
			}
		}
	}()

	// Wait until Ctrl+C pressed
	<-ctrlC
}
