package control

import (
	"fmt"
	"strings"

	"tuncat/internal/engine"
	"tuncat/internal/engine/auth"
	engineconfig "tuncat/internal/engine/config"
	"tuncat/internal/engine/network"
	enginesession "tuncat/internal/engine/session"
	"tuncat/internal/engine/tunnel"
)

func ensureContext(ctx *engine.Context) error {
	if ctx == nil {
		return fmt.Errorf("vpn context is nil")
	}
	if ctx.Cfg == nil {
		ctx.Cfg = engineconfig.NewClientConfig()
	}
	if ctx.LocalInterface == nil {
		ctx.LocalInterface = engineconfig.NewInterface()
	}
	if ctx.Profile == nil {
		ctx.Profile = engine.NewProfile()
	}
	if ctx.Session == nil {
		ctx.Session = &enginesession.Session{}
	}
	if ctx.Auth == nil {
		ctx.Auth = engine.NewAuthState()
	}
	if ctx.Logger == nil {
		ctx.Logger = engineconfig.NewLogger(ctx.Cfg)
	}
	engineconfig.SetDefaultLogger(ctx.Logger)
	return nil
}

func Connect(ctx *engine.Context) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}

	if strings.Contains(ctx.Profile.Host, ":") {
		ctx.Profile.HostWithPort = ctx.Profile.Host
	} else {
		ctx.Profile.HostWithPort = ctx.Profile.Host + ":443"
	}
	if !ctx.Profile.Initialized {
		err := network.GetLocalInterface(ctx)
		if err != nil {
			return err
		}
	}
	err := auth.InitAuth(ctx)
	if err != nil {
		return err
	}
	err = auth.PasswordAuth(ctx)
	if err != nil {
		return err
	}

	return SetupTunnel(false, ctx)
}

func SetupTunnel(reconnect bool, ctx *engine.Context) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}

	if reconnect && !ctx.Profile.Initialized {
		// Refresh local interface details before reconnecting after link changes.
		err := network.GetLocalInterface(ctx)
		if err != nil {
			return err
		}
	}
	return tunnel.SetupTunnel(ctx)
}

func DisConnect(ctx *engine.Context) {
	if err := ensureContext(ctx); err != nil {
		return
	}
	ctx.Session.ActiveClose = true
	if ctx.Session.CSess != nil {
		network.ResetRoutes(ctx, ctx.Session.CSess)
		ctx.Session.CSess.Close()
	}
}
