package logger

import (
	"log"
	"os"

	"github.com/fatih/color"
	"go.uber.org/zap"
)

var (
	logger        *zap.Logger
	Sugar         *zap.SugaredLogger
	ClusterLogger *log.Logger
	// color output
	Red     = color.New(color.FgHiRed)
	Cyan    = color.New(color.FgCyan).Add(color.Bold)
	Green   = color.New(color.FgGreen).Add(color.Bold)
	Magenta = color.New(color.FgHiMagenta).Add(color.Italic)
)

func InitLogger() (err error) {
	ClusterLogger = log.New(os.Stderr, "[CLUSTER] ", log.LstdFlags|log.Lshortfile|log.LUTC)
	logger, err = zap.NewProduction()
	Sugar = logger.Sugar()
	return err
}

func Close() {
	logger.Sync()
}
