package net

import (
	"os"
	"syscall"

	"github.com/alex60217101990/packets-dump/internal/logger"
)

func SetLimit() (err error) {
	var rLimit syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		logger.Sugar.Error(err)
		os.Exit(1)
		return err
	}
	rLimit.Cur = rLimit.Max
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		logger.Sugar.Error(err)
		os.Exit(1)
	}

	return err
}
