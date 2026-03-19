package rpc

import (
	"fmt"
	"strings"

	vpncore "tuncat/internal/vpncore"
	"tuncat/internal/vpncore/auth"
	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/session"
	"tuncat/internal/vpncore/utils/vpnc"
	"tuncat/internal/vpncore/vpn"
)

func ensureContext(ctx *vpncore.VPNContext) error {
	if ctx == nil {
		return fmt.Errorf("vpn context is nil")
	}
	if ctx.Cfg == nil {
		ctx.Cfg = base.NewClientConfig()
	}
	if ctx.LocalInterface == nil {
		ctx.LocalInterface = base.NewInterface()
	}
	if ctx.Profile == nil {
		ctx.Profile = vpncore.NewProfile()
	}
	if ctx.Session == nil {
		ctx.Session = &session.Session{}
	}
	if ctx.Auth == nil {
		ctx.Auth = vpncore.NewAuthState()
	}
	if ctx.Logger == nil {
		ctx.Logger = base.NewLogger(ctx.Cfg)
	}
	base.SetDefaultLogger(ctx.Logger)
	return nil
}

func Connect(ctx *vpncore.VPNContext) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}

	if strings.Contains(ctx.Profile.Host, ":") {
		ctx.Profile.HostWithPort = ctx.Profile.Host
	} else {
		ctx.Profile.HostWithPort = ctx.Profile.Host + ":443"
	}
	if !ctx.Profile.Initialized {
		err := vpnc.GetLocalInterface(ctx)
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

func SetupTunnel(reconnect bool, ctx *vpncore.VPNContext) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}

	if reconnect && !ctx.Profile.Initialized {
		// Refresh local interface details before reconnecting after link changes.
		err := vpnc.GetLocalInterface(ctx)
		if err != nil {
			return err
		}
	}
	return vpn.SetupTunnel(ctx)
}

func DisConnect(ctx *vpncore.VPNContext) {
	if err := ensureContext(ctx); err != nil {
		return
	}
	ctx.Session.ActiveClose = true
	if ctx.Session.CSess != nil {
		vpnc.ResetRoutes(ctx, ctx.Session.CSess)
		ctx.Session.CSess.Close()
	}
}
