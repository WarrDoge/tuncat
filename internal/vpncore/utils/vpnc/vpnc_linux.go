package vpnc

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	vpncore "tuncat/internal/vpncore"
	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/session"
	"tuncat/internal/vpncore/tun"
	"tuncat/internal/vpncore/utils"
)

type RoutingState struct {
	localInterface netlink.Link
	iface          netlink.Link
	resolvBackupOK bool
}

const (
	linuxResolvConfPath = "/etc/resolv.conf"
	linuxResolvBackup   = "/run/tuncat/resolv.conf.bak"
)

func routingState(ctx *vpncore.VPNContext) *RoutingState {
	if ctx == nil {
		return &RoutingState{}
	}
	if state, ok := ctx.RoutingState.(*RoutingState); ok && state != nil {
		return state
	}
	state := &RoutingState{}
	ctx.RoutingState = state
	return state
}

func ConfigInterface(ctx *vpncore.VPNContext, cSess *session.ConnSession, _ tun.Device) error {
	state := routingState(ctx)

	iface, err := netlink.LinkByName(cSess.TunName)
	if err != nil {
		return err
	}
	state.iface = iface

	_ = netlink.LinkSetUp(state.iface)
	_ = netlink.LinkSetMulticastOff(state.iface)

	addr, _ := netlink.ParseAddr(utils.IpMask2CIDR(cSess.VPNAddress, cSess.VPNMask))
	return netlink.AddrAdd(state.iface, addr)
}

func SetRoutes(ctx *vpncore.VPNContext, cSess *session.ConnSession) error {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil || state.localInterface == nil || state.iface == nil {
		return fmt.Errorf("routing state is not initialized")
	}
	handle, err := netlink.NewHandle(netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	defer handle.Close()

	dst, _ := netlink.ParseIPNet(cSess.ServerAddress + "/32")
	gateway := net.ParseIP(ctx.LocalInterface.Gateway)

	ifaceIndex := state.iface.Attrs().Index
	localInterfaceIndex := state.localInterface.Attrs().Index

	route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
	err = handle.RouteAdd(&route)
	if err != nil && !strings.HasSuffix(err.Error(), "exists") {
		return routingError(dst, err)
	}

	splitInclude := cSess.SplitInclude
	if ctx.Cfg != nil && len(ctx.Cfg.SplitRoutes) > 0 {
		splitInclude = append([]string(nil), ctx.Cfg.SplitRoutes...)
	}

	if len(splitInclude) == 0 {
		splitInclude = append(splitInclude, "0.0.0.0/0.0.0.0")

		zero, _ := netlink.ParseIPNet("0.0.0.0/0")
		_ = delAllRoute(handle, &netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST)
		_ = handle.RouteAdd(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero, Gw: gateway, Priority: 10})
	}
	cSess.SplitInclude = splitInclude

	for _, routeSpec := range cSess.SplitInclude {
		cidr, routeErr := routeToCIDR(routeSpec)
		if routeErr != nil {
			return routeErr
		}
		dst, _ = netlink.ParseIPNet(cidr)
		route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 6}
		err = handle.RouteAdd(&route)
		if err != nil && !strings.HasSuffix(err.Error(), "exists") {
			return routingError(dst, err)
		}
	}

	for _, routeSpec := range cSess.SplitExclude {
		cidr, routeErr := routeToCIDR(routeSpec)
		if routeErr != nil {
			return routeErr
		}
		dst, _ = netlink.ParseIPNet(cidr)
		route = netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway, Priority: 5}
		err = handle.RouteAdd(&route)
		if err != nil && !strings.HasSuffix(err.Error(), "exists") {
			return routingError(dst, err)
		}
	}

	if len(cSess.DNS) > 0 {
		setDNS(ctx, cSess)
	}

	return nil
}

func ResetRoutes(ctx *vpncore.VPNContext, cSess *session.ConnSession) {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil || state.localInterface == nil || state.iface == nil {
		return
	}
	handle, err := netlink.NewHandle(netlink.FAMILY_V4)
	if err != nil {
		return
	}
	defer handle.Close()

	ifaceIndex := state.iface.Attrs().Index
	localInterfaceIndex := state.localInterface.Attrs().Index

	for _, ipMask := range cSess.SplitInclude {
		if ipMask == "0.0.0.0/0.0.0.0" || ipMask == "0.0.0.0/0" {
			zero, _ := netlink.ParseIPNet("0.0.0.0/0")
			gateway := net.ParseIP(ctx.LocalInterface.Gateway)
			_ = handle.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero})
			_ = handle.RouteAdd(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero, Gw: gateway})
			break
		}
	}

	dst, _ := netlink.ParseIPNet(cSess.ServerAddress + "/32")
	_ = handle.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})

	for _, routeSpec := range cSess.SplitInclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			continue
		}
		dst, _ = netlink.ParseIPNet(cidr)
		_ = handle.RouteDel(&netlink.Route{LinkIndex: ifaceIndex, Dst: dst})
	}

	for _, routeSpec := range cSess.SplitExclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			continue
		}
		dst, _ = netlink.ParseIPNet(cidr)
		_ = handle.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})
	}

	if len(cSess.DynamicSplitExcludeDomains) > 0 {
		cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				dst, _ = netlink.ParseIPNet(ip + "/32")
				_ = handle.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})
			}

			return true
		})
	}

	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		cSess.DynamicSplitIncludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				dst, _ = netlink.ParseIPNet(ip + "/32")
				_ = handle.RouteDel(&netlink.Route{LinkIndex: ifaceIndex, Dst: dst})
			}

			return true
		})
	}

	if len(cSess.DNS) > 0 {
		restoreDNS(ctx, cSess)
	}
}

func DynamicAddIncludeRoutes(ctx *vpncore.VPNContext, ips []string) {
	state := routingState(ctx)
	if state.iface == nil {
		return
	}
	ifaceIndex := state.iface.Attrs().Index

	for _, ip := range ips {
		dst, _ := netlink.ParseIPNet(ip + "/32")
		route := netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 6}
		_ = netlink.RouteAdd(&route)
	}
}

func DynamicAddExcludeRoutes(ctx *vpncore.VPNContext, ips []string) {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil || state.localInterface == nil {
		return
	}
	localInterfaceIndex := state.localInterface.Attrs().Index
	gateway := net.ParseIP(ctx.LocalInterface.Gateway)

	for _, ip := range ips {
		dst, _ := netlink.ParseIPNet(ip + "/32")
		route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway, Priority: 5}
		_ = netlink.RouteAdd(&route)
	}
}

func GetLocalInterface(ctx *vpncore.VPNContext) error {
	if ctx == nil || ctx.LocalInterface == nil {
		return fmt.Errorf("vpn context local interface is nil")
	}
	state := routingState(ctx)

	routes, err := netlink.RouteGet(net.ParseIP("8.8.8.8"))
	if len(routes) > 0 {
		route := routes[0]
		state.localInterface, err = netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return err
		}
		ctx.LocalInterface.Name = state.localInterface.Attrs().Name
		ctx.LocalInterface.Ip4 = route.Src.String()
		ctx.LocalInterface.Gateway = route.Gw.String()
		ctx.LocalInterface.Mac = state.localInterface.Attrs().HardwareAddr.String()

		base.Info("GetLocalInterface:", fmt.Sprintf("%+v", *ctx.LocalInterface))
		return nil
	}
	return err
}

func delAllRoute(handle *netlink.Handle, filter *netlink.Route, filterMask uint64) error {
	routes, err := handle.RouteListFiltered(netlink.FAMILY_V4, filter, filterMask)
	if err != nil {
		return err
	}
	for i := range routes {
		route := routes[i]
		if err := handle.RouteDel(&route); err != nil {
			return err
		}
	}
	return nil
}

func routingError(dst *net.IPNet, err error) error {
	return fmt.Errorf("routing error: %s %s", dst.String(), err)
}

func setDNS(ctx *vpncore.VPNContext, cSess *session.ConnSession) {
	if len(cSess.DNS) == 0 {
		return
	}
	state := routingState(ctx)

	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		DynamicAddIncludeRoutes(ctx, cSess.DNS)
	}

	if !state.resolvBackupOK {
		if err := os.MkdirAll("/run/tuncat", 0o700); err != nil {
			base.Warn("create /run/tuncat failed:", err)
		} else if err := utils.CopyFile(linuxResolvBackup, linuxResolvConfPath); err == nil {
			state.resolvBackupOK = true
		} else {
			base.Warn("backup resolv.conf failed:", err)
		}
	}

	var dnsBuilder strings.Builder
	for _, dns := range cSess.DNS {
		_, _ = fmt.Fprintf(&dnsBuilder, "nameserver %s\n", dns)
	}
	domains := []string{}
	if ctx != nil && ctx.Cfg != nil {
		domains = NormalizeDNSDomains(ctx.Cfg.DNSDomains)
	}
	if len(domains) > 0 {
		dnsBuilder.WriteString("search ")
		dnsBuilder.WriteString(strings.Join(domains, " "))
		dnsBuilder.WriteString("\n")
	}

	err := os.WriteFile(linuxResolvConfPath, []byte(dnsBuilder.String()), 0o644)
	if err != nil {
		base.Error("set DNS failed:", err)
	}
}

func restoreDNS(ctx *vpncore.VPNContext, cSess *session.ConnSession) {
	if len(cSess.DNS) == 0 {
		return
	}
	state := routingState(ctx)

	if state.resolvBackupOK {
		if err := utils.CopyFile(linuxResolvConfPath, linuxResolvBackup); err != nil {
			base.Warn("restore resolv.conf failed:", err)
		} else {
			_ = os.Remove(linuxResolvBackup)
			state.resolvBackupOK = false
		}
	}
}
