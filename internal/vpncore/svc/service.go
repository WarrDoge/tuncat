package svc

import (
	"context"
	"fmt"
	"runtime"

	"github.com/kardianos/service"
	vpncore "tuncat/internal/vpncore"
	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/rpc"
)

type program struct {
	server *rpc.RPCServer
}

var logger service.Logger

var (
	serviceConfig *service.Config
	prg           = &program{}
)

func init() {
	svcName := "tuncat-vpncore"
	if runtime.GOOS == "windows" {
		svcName = "TuncatVpnCore"
	}
	serviceConfig = &service.Config{
		Name:        svcName,
		DisplayName: "Tuncat VPN Core Agent",
		Description: "Tuncat embedded VPN core service agent",
	}
}

// Start should not block. Do the actual work async.
func (p *program) Start(s service.Service) error {
	if service.Interactive() {
		logger.Info("Running in terminal.")
	} else {
		logger.Info("Running under service manager.")
	}
	go p.run()
	return nil
}

// Stop should not block. Return with a few seconds.
func (p *program) Stop(s service.Service) error {
	logger.Info("I'm Stopping!")
	base.Info("Stop")
	if p.server != nil {
		p.server.DisConnect()
		_ = p.server.Shutdown(context.Background())
	}
	return nil
}

func (p *program) run() {
	ctx := vpncore.NewVPNContext()
	ctx.Logger = base.InitLog(ctx.Cfg)
	p.server = rpc.NewRPCServer(ctx)
	if err := p.server.Setup(); err != nil {
		base.Fatal(err)
	}
}

func RunSvc() {
	svc, err := service.New(prg, serviceConfig)
	if err != nil {
		fmt.Println("Cannot create the service: " + err.Error())
	}
	errs := make(chan error, 5)
	logger, err = svc.Logger(errs)
	if err != nil {
		fmt.Println("Cannot open a system logger: " + err.Error())
	}
	err = svc.Run()
	if err != nil {
		fmt.Println("Cannot start the service: " + err.Error())
	}
}

func InstallSvc() {
	svc, err := service.New(prg, serviceConfig)
	if err != nil {
		fmt.Println("Cannot create the service: " + err.Error())
	}
	err = svc.Install()
	if err != nil {
		fmt.Println("Cannot install the service: " + err.Error())
	} else {
		err := svc.Start()
		if err != nil {
			fmt.Println("Cannot start the service: " + err.Error())
		}
	}
}

func UninstallSvc() {
	svc, err := service.New(prg, serviceConfig)
	if err != nil {
		fmt.Println("Cannot create the service: " + err.Error())
	} else {
		err := svc.Stop()
		if err != nil {
			fmt.Println("Cannot stop the service: " + err.Error())
		}
		err = svc.Uninstall()
		if err != nil {
			fmt.Println("Cannot uninstall the service: " + err.Error())
		}
	}
}
