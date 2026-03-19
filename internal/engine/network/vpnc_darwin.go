package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/jackpal/gateway"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tuncat/internal/engine"
	engineconfig "tuncat/internal/engine/config"
	"tuncat/internal/engine/device"
	enginesession "tuncat/internal/engine/session"
)

const (
	darwinResolverDir        = "/etc/resolver"
	darwinResolverMarker     = "# managed by tuncat"
	darwinResolvConfPath     = "/etc/resolv.conf"
	darwinResolvConfBackup   = "/var/run/tuncat/resolv.conf.bak"
	darwinResolverFilePerm   = 0o644
	darwinResolverFolderPerm = 0o755
)

type RoutingState struct {
	vpnAddress        string
	tunName           string
	routeSequence     uint32
	resolvBackupReady bool
}

func routingState(ctx *engine.Context) *RoutingState {
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

func ConfigInterface(ctx *engine.Context, cSess *enginesession.ConnSession, _ device.Device) error {
	state := routingState(ctx)
	state.vpnAddress = cSess.VPNAddress
	state.tunName = cSess.TunName
	return configureDarwinInterface(cSess.TunName, cSess.VPNAddress)
}

func SetRoutes(ctx *engine.Context, cSess *enginesession.ConnSession) error {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil {
		return fmt.Errorf("vpn context local interface is nil")
	}

	if err := addRoute(cSess.ServerAddress+"/32", ctx.LocalInterface.Gateway, ctx.LocalInterface.Name, state); err != nil {
		return routingError(cSess.ServerAddress+"/32", err)
	}

	splitInclude := cSess.SplitInclude
	if ctx.Cfg != nil && len(ctx.Cfg.SplitRoutes) > 0 {
		splitInclude = append([]string(nil), ctx.Cfg.SplitRoutes...)
	}
	cSess.SplitInclude = splitInclude

	for _, routeSpec := range cSess.SplitInclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			return err
		}
		if err = addRoute(cidr, cSess.VPNAddress, cSess.TunName, state); err != nil {
			return routingError(cidr, err)
		}
	}

	for _, routeSpec := range cSess.SplitExclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			return err
		}
		if err = addRoute(cidr, ctx.LocalInterface.Gateway, ctx.LocalInterface.Name, state); err != nil {
			return routingError(cidr, err)
		}
	}

	if len(cSess.DNS) > 0 {
		return setDNS(ctx, cSess)
	}

	return nil
}

func ResetRoutes(ctx *engine.Context, cSess *enginesession.ConnSession) {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil {
		return
	}

	_ = deleteRoute(cSess.ServerAddress+"/32", ctx.LocalInterface.Gateway, ctx.LocalInterface.Name, state)

	for _, routeSpec := range cSess.SplitInclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			continue
		}
		_ = deleteRoute(cidr, cSess.VPNAddress, cSess.TunName, state)
	}

	for _, routeSpec := range cSess.SplitExclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			continue
		}
		_ = deleteRoute(cidr, ctx.LocalInterface.Gateway, ctx.LocalInterface.Name, state)
	}

	if len(cSess.DynamicSplitExcludeDomains) > 0 {
		cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				_ = deleteRoute(ip+"/32", ctx.LocalInterface.Gateway, ctx.LocalInterface.Name, state)
			}

			return true
		})
	}

	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		cSess.DynamicSplitIncludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				_ = deleteRoute(ip+"/32", state.vpnAddress, cSess.TunName, state)
			}

			return true
		})
	}

	if len(cSess.DNS) > 0 {
		restoreDNS(ctx, cSess)
	}
}

func DynamicAddIncludeRoutes(ctx *engine.Context, ips []string) {
	state := routingState(ctx)
	if state.tunName == "" {
		return
	}
	for _, ip := range ips {
		_ = addRoute(ip+"/32", state.vpnAddress, state.tunName, state)
	}
}

func DynamicAddExcludeRoutes(ctx *engine.Context, ips []string) {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil {
		return
	}
	for _, ip := range ips {
		_ = addRoute(ip+"/32", ctx.LocalInterface.Gateway, ctx.LocalInterface.Name, state)
	}
}

func GetLocalInterface(ctx *engine.Context) error {
	if ctx == nil || ctx.LocalInterface == nil {
		return fmt.Errorf("vpn context local interface is nil")
	}

	localInterfaceIP, err := gateway.DiscoverInterface()
	if err != nil {
		return err
	}
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return err
	}

	localInterface := net.Interface{}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP.To4()
			if ip.Equal(localInterfaceIP) {
				localInterface = iface
				break
			}
		}
	}

	ctx.LocalInterface.Name = localInterface.Name
	ctx.LocalInterface.Ip4 = localInterfaceIP.String()
	ctx.LocalInterface.Gateway = gatewayIP.String()
	ctx.LocalInterface.Mac = localInterface.HardwareAddr.String()

	engineconfig.Info("GetLocalInterface:", fmt.Sprintf("%+v", *ctx.LocalInterface))

	return nil
}

func routingError(dst string, err error) error {
	return fmt.Errorf("routing error: %s %s", dst, err)
}

// Known exception: Darwin still relies on the system's ifconfig binary to assign
// the utun IPv4 address until a verified ioctl-based implementation is in place.
// This is the only remaining non-pure-Go runtime step in tuncat.
func configureDarwinInterface(ifName, vpnAddress string) error {
	ifconfigPath, err := exec.LookPath("ifconfig")
	if err != nil {
		return fmt.Errorf("ifconfig not found: %w", err)
	}

	cmd := exec.Command(
		ifconfigPath,
		ifName,
		"inet",
		vpnAddress,
		vpnAddress,
		"netmask",
		"255.255.255.255",
		"up",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func setDNS(ctx *engine.Context, cSess *enginesession.ConnSession) error {
	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		DynamicAddIncludeRoutes(ctx, cSess.DNS)
	}

	domains := []string{}
	if ctx != nil && ctx.Cfg != nil {
		domains = NormalizeDNSDomains(ctx.Cfg.DNSDomains)
	}
	if len(domains) > 0 {
		return setSplitDNS(cSess.DNS, domains)
	}

	return setGlobalDNS(routingState(ctx), cSess.DNS)
}

func restoreDNS(ctx *engine.Context, cSess *enginesession.ConnSession) {
	state := routingState(ctx)
	if err := clearManagedResolvers(nil); err != nil {
		engineconfig.Warn("cleanup macOS resolver files failed:", err)
	}

	if state.resolvBackupReady {
		if err := copyFile(darwinResolvConfPath, darwinResolvConfBackup); err != nil {
			engineconfig.Warn("restore /etc/resolv.conf failed:", err)
		} else {
			_ = os.Remove(darwinResolvConfBackup)
			state.resolvBackupReady = false
		}
	}
}

func setSplitDNS(dns []string, domains []string) error {
	if err := os.MkdirAll(darwinResolverDir, darwinResolverFolderPerm); err != nil {
		return err
	}

	keep := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		keep[domain] = struct{}{}
	}
	if err := clearManagedResolvers(keep); err != nil {
		return err
	}

	resolverContent := buildResolverContent(dns)
	for _, domain := range domains {
		resolverPath := filepath.Join(darwinResolverDir, domain)

		if existing, err := os.ReadFile(resolverPath); err == nil {
			if !isManagedResolver(existing) {
				engineconfig.Warn("skip unmanaged resolver file:", resolverPath)
				continue
			}
		} else if !os.IsNotExist(err) {
			return err
		}

		if err := os.WriteFile(resolverPath, []byte(resolverContent), darwinResolverFilePerm); err != nil {
			return err
		}
	}

	return nil
}

func setGlobalDNS(state *RoutingState, dns []string) error {
	if !state.resolvBackupReady {
		if err := os.MkdirAll("/var/run/tuncat", 0o700); err != nil {
			return err
		}
		if err := copyFile(darwinResolvConfBackup, darwinResolvConfPath); err != nil {
			return err
		}
		state.resolvBackupReady = true
	}

	var builder strings.Builder
	builder.WriteString(darwinResolverMarker)
	builder.WriteString("\n")
	for _, server := range dns {
		builder.WriteString("nameserver ")
		builder.WriteString(server)
		builder.WriteString("\n")
	}

	return os.WriteFile(darwinResolvConfPath, []byte(builder.String()), darwinResolverFilePerm)
}

func clearManagedResolvers(keep map[string]struct{}) error {
	entries, err := os.ReadDir(darwinResolverDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if keep != nil {
			if _, shouldKeep := keep[entry.Name()]; shouldKeep {
				continue
			}
		}

		resolverPath := filepath.Join(darwinResolverDir, entry.Name())
		content, err := os.ReadFile(resolverPath)
		if err != nil {
			continue
		}
		if !isManagedResolver(content) {
			continue
		}
		if err := os.Remove(resolverPath); err != nil {
			return err
		}
	}

	return nil
}

func isManagedResolver(content []byte) bool {
	return strings.Contains(string(content), darwinResolverMarker)
}

func buildResolverContent(dns []string) string {
	var builder strings.Builder
	builder.WriteString(darwinResolverMarker)
	builder.WriteString("\n")
	for _, server := range dns {
		builder.WriteString("nameserver ")
		builder.WriteString(server)
		builder.WriteString("\n")
	}

	return builder.String()
}

func copyFile(dstName, srcName string) error {
	input, err := os.ReadFile(srcName)
	if err != nil {
		return err
	}

	return os.WriteFile(dstName, input, darwinResolverFilePerm)
}

func addRoute(cidr, gateway, ifName string, state *RoutingState) error {
	err := applyRoute(unix.RTM_ADD, cidr, gateway, ifName, state)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	return nil
}

func deleteRoute(cidr, gateway, ifName string, state *RoutingState) error {
	err := applyRoute(unix.RTM_DELETE, cidr, gateway, ifName, state)
	if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
		return err
	}

	return nil
}

func applyRoute(msgType int, cidr, gateway, ifName string, state *RoutingState) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	dstIP := dst.IP.To4()
	if dstIP == nil {
		return fmt.Errorf("only IPv4 routes are supported: %s", cidr)
	}

	gwIP := net.ParseIP(gateway).To4()
	if gwIP == nil {
		return fmt.Errorf("invalid route gateway: %q", gateway)
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}

	maskIP := net.IP(dst.Mask).To4()
	if maskIP == nil {
		return fmt.Errorf("invalid netmask for route: %s", cidr)
	}

	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = inet4Addr(dstIP)
	addrs[unix.RTAX_GATEWAY] = inet4Addr(gwIP)
	addrs[unix.RTAX_NETMASK] = inet4Addr(maskIP)

	flags := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY
	ones, bits := dst.Mask.Size()
	if bits == 32 && ones == 32 {
		flags |= unix.RTF_HOST
	}

	seq := uint32(0)
	if state != nil {
		seq = atomic.AddUint32(&state.routeSequence, 1)
	}

	message := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    msgType,
		Flags:   flags,
		Index:   iface.Index,
		ID:      uintptr(os.Getpid()),
		Seq:     int(seq),
		Addrs:   addrs,
	}

	payload, err := message.Marshal()
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	_, err = unix.Write(fd, payload)
	return err
}

func inet4Addr(ip net.IP) *route.Inet4Addr {
	ip4 := ip.To4()
	if ip4 == nil {
		return &route.Inet4Addr{}
	}

	return &route.Inet4Addr{IP: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}
}
