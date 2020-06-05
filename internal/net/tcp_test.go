package net

import (
	"bytes"
	"encoding/gob"
	"math/rand"
	"testing"
	"time"

	"github.com/alex60217101990/packets-dump/internal/logger"
	"github.com/alex60217101990/types/enums"
	"github.com/alex60217101990/types/models"
)

func init() {
	logger.InitLogger()
}

func TestGobEncodeDecode(t *testing.T) {
	defer func() {
		logger.Close()
	}()
	rand.Seed(time.Now().Unix())
	testMsg := []models.SidecarEvent{
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
	network := new(bytes.Buffer)
	enc := gob.NewEncoder(network)
	for i := 0; i < 10; i++ {
		inter := testMsg[rand.Intn(len(testMsg))]
		err := enc.Encode(&inter)
		if err != nil {
			t.Error(err)
			return
		}
	}
	dec := gob.NewDecoder(network)
	for i := 0; i < 10; i++ {
		var get models.SidecarEvent
		err := dec.Decode(&get)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(get.GetValue())
	}
}

func TestTCPServer(t *testing.T) {
	serv := NewTCPServer()
	serv.Run()
	defer func() {
		serv.Close()
		logger.Close()
	}()
	<-time.After(time.Second * 30)
}
