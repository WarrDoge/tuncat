package vpnc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	vpncore "tuncat/internal/vpncore"
	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/session"
	"tuncat/internal/vpncore/tun"
	"tuncat/internal/vpncore/utils"
)

const (
	nrptRulePrefix        = "tuncat-"
	nrptBasePath          = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptConfigGenericDNS  = 0x00000008
	nrptRuleVersion       = 1
	nrptManagedRuleNote   = "managed by tuncat"
	nrptRegistryWriteMask = registry.QUERY_VALUE | registry.SET_VALUE | registry.CREATE_SUB_KEY | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY
	nrptRegistryReadMask  = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY
	windowsRollbackFile   = "windows-network-state.json"
)

type RoutingState struct {
	localInterface     winipcfg.LUID
	iface              winipcfg.LUID
	nextHopVPN         netip.Addr
	nextHopGateway     netip.Addr
	previousDNSServers []netip.Addr
	dnsStateCaptured   bool
	staleRollbackClean bool
}

type rollbackState struct {
	PreviousDNSServers []string `json:"previous_dns_servers,omitempty"`
}

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

func ConfigInterface(ctx *vpncore.VPNContext, cSess *session.ConnSession, dev tun.Device) error {
	state := routingState(ctx)
	native, ok := dev.(*tun.NativeTun)
	if !ok {
		return fmt.Errorf("unsupported Windows tun device type %T", dev)
	}

	state.iface = native.LUID()

	mtu, _ := native.MTU()
	if err := SetMTU(state.iface, mtu); err != nil {
		return err
	}

	state.iface.FlushIPAddresses(windows.AF_UNSPEC)

	state.nextHopVPN, _ = netip.ParseAddr(cSess.VPNAddress)
	prefixVPN, _ := netip.ParsePrefix(utils.IpMask2CIDR(cSess.VPNAddress, cSess.VPNMask))
	return state.iface.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{prefixVPN})
}

func SetRoutes(ctx *vpncore.VPNContext, cSess *session.ConnSession) error {
	state := routingState(ctx)
	if ctx == nil || ctx.LocalInterface == nil {
		return fmt.Errorf("vpn context local interface is nil")
	}
	if state.localInterface == 0 || state.iface == 0 {
		return fmt.Errorf("routing interfaces are not initialized")
	}
	if !state.staleRollbackClean {
		if err := cleanupStaleRollback(state); err != nil {
			base.Warn("stale Windows rollback cleanup failed:", err)
		}
		state.staleRollbackClean = true
	}

	dst, err := netip.ParsePrefix(cSess.ServerAddress + "/32")
	state.nextHopGateway, _ = netip.ParseAddr(ctx.LocalInterface.Gateway)
	err = state.localInterface.AddRoute(dst, state.nextHopGateway, 5)
	if err != nil && !strings.HasSuffix(err.Error(), "exists.") {
		return routingError(dst, err)
	}

	splitInclude := cSess.SplitInclude
	if ctx.Cfg != nil && len(ctx.Cfg.SplitRoutes) > 0 {
		splitInclude = append([]string(nil), ctx.Cfg.SplitRoutes...)
	}
	if len(splitInclude) == 0 {
		splitInclude = append(splitInclude, "0.0.0.0/0.0.0.0")
	}
	cSess.SplitInclude = splitInclude

	for _, routeSpec := range cSess.SplitInclude {
		cidr, routeErr := routeToCIDR(routeSpec)
		if routeErr != nil {
			return routeErr
		}
		dst, _ = netip.ParsePrefix(cidr)
		err = state.iface.AddRoute(dst, state.nextHopVPN, 6)
		if err != nil && !strings.HasSuffix(err.Error(), "exists.") {
			return routingError(dst, err)
		}
	}

	for _, routeSpec := range cSess.SplitExclude {
		cidr, routeErr := routeToCIDR(routeSpec)
		if routeErr != nil {
			return routeErr
		}
		dst, _ = netip.ParsePrefix(cidr)
		err = state.localInterface.AddRoute(dst, state.nextHopGateway, 5)
		if err != nil && !strings.HasSuffix(err.Error(), "exists.") {
			return routingError(dst, err)
		}
	}

	if len(cSess.DNS) > 0 {
		err = setDNS(ctx, cSess)
	}
	return err
}

func ResetRoutes(ctx *vpncore.VPNContext, cSess *session.ConnSession) {
	state := routingState(ctx)
	if state.localInterface == 0 || state.iface == 0 {
		return
	}

	dst, _ := netip.ParsePrefix(cSess.ServerAddress + "/32")
	_ = state.localInterface.DeleteRoute(dst, state.nextHopGateway)

	for _, routeSpec := range cSess.SplitInclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			continue
		}
		dst, _ = netip.ParsePrefix(cidr)
		_ = state.iface.DeleteRoute(dst, state.nextHopVPN)
	}

	for _, routeSpec := range cSess.SplitExclude {
		cidr, err := routeToCIDR(routeSpec)
		if err != nil {
			continue
		}
		dst, _ = netip.ParsePrefix(cidr)
		_ = state.localInterface.DeleteRoute(dst, state.nextHopGateway)
	}

	if len(cSess.DynamicSplitExcludeDomains) > 0 {
		cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				dst, _ = netip.ParsePrefix(ip + "/32")
				_ = state.localInterface.DeleteRoute(dst, state.nextHopGateway)
			}

			return true
		})
	}

	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		cSess.DynamicSplitIncludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				dst, _ = netip.ParsePrefix(ip + "/32")
				_ = state.iface.DeleteRoute(dst, state.nextHopVPN)
			}

			return true
		})
	}

	restoreDNS(ctx)
}

func DynamicAddIncludeRoutes(ctx *vpncore.VPNContext, ips []string) {
	state := routingState(ctx)
	if state.iface == 0 {
		return
	}
	for _, ip := range ips {
		dst, _ := netip.ParsePrefix(ip + "/32")
		_ = state.iface.AddRoute(dst, state.nextHopVPN, 6)
	}
}

func DynamicAddExcludeRoutes(ctx *vpncore.VPNContext, ips []string) {
	state := routingState(ctx)
	if state.localInterface == 0 {
		return
	}
	for _, ip := range ips {
		dst, _ := netip.ParsePrefix(ip + "/32")
		_ = state.localInterface.AddRoute(dst, state.nextHopGateway, 5)
	}
}

func GetLocalInterface(ctx *vpncore.VPNContext) error {
	if ctx == nil || ctx.LocalInterface == nil {
		return fmt.Errorf("vpn context local interface is nil")
	}
	state := routingState(ctx)

	ifcs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return err
	}

	var primaryInterface *winipcfg.IPAdapterAddresses
	var virtualPrimaryInterface *winipcfg.IPAdapterAddresses
	for _, ifc := range ifcs {
		base.Debug(ifc.AdapterName(), ifc.Description(), ifc.FriendlyName(), ifc.Ipv4Metric, ifc.IfType)
		if (ifc.IfType == 6 || ifc.IfType == 71) && ifc.FirstGatewayAddress != nil {
			if primaryInterface == nil || (ifc.Ipv4Metric < primaryInterface.Ipv4Metric) {
				if !strings.Contains(ifc.Description(), "Virtual") {
					primaryInterface = ifc
				} else if virtualPrimaryInterface == nil {
					virtualPrimaryInterface = ifc
				}
			}
		}
	}

	if primaryInterface == nil {
		if virtualPrimaryInterface != nil {
			primaryInterface = virtualPrimaryInterface
		} else {
			return fmt.Errorf("unable to find a valid network interface")
		}
	}

	base.Info("GetLocalInterface:", primaryInterface.AdapterName(), primaryInterface.Description(),
		primaryInterface.FriendlyName(), primaryInterface.Ipv4Metric, primaryInterface.IfType)

	ctx.LocalInterface.Name = primaryInterface.FriendlyName()
	ctx.LocalInterface.Ip4 = primaryInterface.FirstUnicastAddress.Address.IP().String()
	ctx.LocalInterface.Gateway = primaryInterface.FirstGatewayAddress.Address.IP().String()
	ctx.LocalInterface.Mac = net.HardwareAddr(primaryInterface.PhysicalAddress()).String()

	state.localInterface = primaryInterface.LUID

	return nil
}

func SetMTU(luid winipcfg.LUID, mtu int) error {
	ipv4, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return err
	}
	ipv4.NLMTU = uint32(mtu)
	if err := ipv4.Set(); err != nil {
		return err
	}

	if ipv6, err := luid.IPInterface(windows.AF_INET6); err == nil {
		ipv6.NLMTU = uint32(mtu)
		_ = ipv6.Set()
	}

	return nil
}

func routingError(dst netip.Prefix, err error) error {
	return fmt.Errorf("routing error: %s %s", dst.String(), err)
}

func setDNS(ctx *vpncore.VPNContext, cSess *session.ConnSession) error {
	state := routingState(ctx)
	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		DynamicAddIncludeRoutes(ctx, cSess.DNS)
	}

	servers := make([]netip.Addr, 0, len(cSess.DNS))
	for _, dns := range cSess.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			continue
		}
		servers = append(servers, addr)
	}

	if len(servers) == 0 {
		return fmt.Errorf("no valid DNS servers provided by VPN")
	}

	if !state.dnsStateCaptured {
		if current, err := state.iface.DNS(); err == nil {
			state.previousDNSServers = append([]netip.Addr(nil), current...)
			state.dnsStateCaptured = true
			if err := persistRollbackState(state); err != nil {
				base.Warn("persist Windows rollback state failed:", err)
			}
		}
	}

	domains := []string{}
	if ctx != nil && ctx.Cfg != nil {
		domains = NormalizeDNSDomains(ctx.Cfg.DNSDomains)
	}
	err := state.iface.SetDNS(windows.AF_INET, servers, domains)
	if err != nil {
		return err
	}

	if err := applyNRPTRules(domains, servers); err != nil {
		base.Warn("NRPT configuration failed:", err)
	}

	return nil
}

func restoreDNS(ctx *vpncore.VPNContext) {
	state := routingState(ctx)
	if err := clearOwnedNRPTRules(); err != nil {
		base.Warn("NRPT cleanup failed:", err)
	}

	if state.dnsStateCaptured {
		if err := state.iface.SetDNS(windows.AF_INET, state.previousDNSServers, []string{}); err != nil {
			base.Warn("restore DNS servers failed:", err)
		}
		state.previousDNSServers = nil
		state.dnsStateCaptured = false
	}
	if err := clearRollbackState(); err != nil {
		base.Warn("clear Windows rollback state failed:", err)
	}
}

func applyNRPTRules(domains []string, servers []netip.Addr) error {
	if err := clearOwnedNRPTRules(); err != nil {
		return err
	}

	if len(domains) == 0 || len(servers) == 0 {
		return nil
	}

	baseKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptBasePath, nrptRegistryWriteMask)
	if err != nil {
		return err
	}
	baseKey.Close()

	dnsValues := make([]string, 0, len(servers))
	for _, server := range servers {
		dnsValues = append(dnsValues, server.String())
	}
	dnsList := strings.Join(dnsValues, ";")

	for _, domain := range domains {
		rulePath := nrptBasePath + `\` + nrptRuleName(domain)
		ruleKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, rulePath, nrptRegistryWriteMask)
		if err != nil {
			return err
		}

		namespace := "." + strings.TrimPrefix(domain, ".")
		setErr := ruleKey.SetDWordValue("Version", nrptRuleVersion)
		if setErr == nil {
			setErr = ruleKey.SetDWordValue("ConfigOptions", nrptConfigGenericDNS)
		}
		if setErr == nil {
			setErr = ruleKey.SetStringsValue("Name", []string{namespace})
		}
		if setErr == nil {
			setErr = ruleKey.SetStringValue("GenericDNSServers", dnsList)
		}
		if setErr == nil {
			_ = ruleKey.SetStringValue("Comment", nrptManagedRuleNote)
		}
		ruleKey.Close()
		if setErr != nil {
			return setErr
		}
	}

	return nil
}

func clearOwnedNRPTRules() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBasePath, nrptRegistryReadMask)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer key.Close()

	ruleNames, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}

	var lastErr error
	for _, name := range ruleNames {
		if !strings.HasPrefix(strings.ToLower(name), nrptRulePrefix) {
			continue
		}
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptBasePath+`\`+name); err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				lastErr = err
			}
		}
	}

	return lastErr
}

func nrptRuleName(domain string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, ".")))
	if normalized == "" {
		return nrptRulePrefix + "default"
	}

	replacer := strings.NewReplacer(".", "-", "*", "star", "/", "-", "\\", "-", ":", "-")
	return nrptRulePrefix + replacer.Replace(normalized)
}

func cleanupStaleRollback(state *RoutingState) error {
	rollback, err := loadRollbackState()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := clearOwnedNRPTRules(); err != nil {
		return err
	}

	if state != nil && state.iface != 0 {
		if err := state.iface.SetDNS(windows.AF_INET, parseRollbackServers(rollback.PreviousDNSServers), []string{}); err != nil {
			return err
		}
	}

	return clearRollbackState()
}

func persistRollbackState(state *RoutingState) error {
	if state == nil {
		return nil
	}

	rollback := rollbackState{
		PreviousDNSServers: make([]string, 0, len(state.previousDNSServers)),
	}
	for _, server := range state.previousDNSServers {
		rollback.PreviousDNSServers = append(rollback.PreviousDNSServers, server.String())
	}

	data, err := json.Marshal(rollback)
	if err != nil {
		return err
	}

	path := rollbackStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

func loadRollbackState() (*rollbackState, error) {
	data, err := os.ReadFile(rollbackStatePath())
	if err != nil {
		return nil, err
	}

	var rollback rollbackState
	if err := json.Unmarshal(data, &rollback); err != nil {
		return nil, err
	}

	return &rollback, nil
}

func clearRollbackState() error {
	err := os.Remove(rollbackStatePath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func rollbackStatePath() string {
	return filepath.Join(os.TempDir(), "tuncat", windowsRollbackFile)
}

func parseRollbackServers(values []string) []netip.Addr {
	servers := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		servers = append(servers, addr)
	}
	return servers
}
