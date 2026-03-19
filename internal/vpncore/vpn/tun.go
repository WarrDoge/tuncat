package vpn

import (
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	vpncore "tuncat/internal/vpncore"
	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/proto"
	"tuncat/internal/vpncore/session"
	"tuncat/internal/vpncore/tun"
	"tuncat/internal/vpncore/utils"
	"tuncat/internal/vpncore/utils/vpnc"
)

func setupTun(ctx *vpncore.VPNContext, cSess *session.ConnSession) error {
	offset := 0
	if runtime.GOOS == "windows" {
		cSess.TunName = "Tuncat"
	} else if runtime.GOOS == "darwin" {
		cSess.TunName = "utun"
		offset = 4
	} else {
		cSess.TunName = "tuncat"
	}
	dev, err := tun.CreateTUN(cSess.TunName, cSess.MTU)
	if err != nil {
		base.Error("failed to creates a new tun interface")
		return err
	}
	if runtime.GOOS == "darwin" {
		cSess.TunName, _ = dev.Name()
	}

	base.Debug("tun device:", cSess.TunName)

	// Configure OS interface state before packet pump goroutines start.
	err = vpnc.ConfigInterface(ctx, cSess, dev)
	if err != nil {
		_ = dev.Close()
		return err
	}

	go tunToPayloadOut(dev, cSess, offset)     // read from apps
	go payloadInToTun(ctx, dev, cSess, offset) // write to apps
	return nil
}

// tunToPayloadOut reads packets from the TUN interface and forwards them to
// either the TLS or DTLS outbound channel.
func tunToPayloadOut(dev tun.Device, cSess *session.ConnSession, offset int) {
	defer func() {
		base.Info("tun to payloadOut exit")
		_ = dev.Close()
	}()
	var (
		err error
		n   int
	)

	for {
		// Payload buffers come from a shared pool and are returned after send.
		pl := getPayloadBuffer()
		n, err = dev.Read(pl.Data, offset)
		if err != nil {
			base.Error("tun to payloadOut error:", err)
			return
		}

		pl.Data = pl.Data[offset : offset+n]

		if cSess.DtlsConnected.Load() {
			select {
			case cSess.PayloadOutDTLS <- pl:
				continue
			case <-cSess.DSess.CloseChan:
				// DTLS disconnected, fall through to TLS
			}
		}
		select {
		case cSess.PayloadOutTLS <- pl:
		case <-cSess.CloseChan:
			return
		}
	}
}

// payloadInToTun writes decrypted VPN payloads back into the local TUN device.
func payloadInToTun(ctx *vpncore.VPNContext, dev tun.Device, cSess *session.ConnSession, offset int) {
	defer func() {
		base.Info("payloadIn to tun exit")
		// Route cleanup is needed on unexpected session termination.
		if !cSess.Sess.ActiveClose {
			vpnc.ResetRoutes(ctx, cSess)
		}
		cSess.Close()
		_ = dev.Close()
	}()

	var (
		err error
		pl  *proto.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadIn:
		case <-cSess.CloseChan:
			return
		}

		if cSess.DynamicSplitTunneling {
			_, srcPort, _, _ := utils.ResolvePacket(pl.Data)
			if srcPort == 53 {
				// DNS responses are inspected to install host routes lazily.
				go dynamicSplitRoutes(ctx, pl.Data, cSess)
			}
		}

		if offset > 0 {
			expand := make([]byte, offset+len(pl.Data))
			copy(expand[offset:], pl.Data)
			_, err = dev.Write(expand, offset)
		} else {
			_, err = dev.Write(pl.Data, offset)
		}

		if err != nil {
			base.Error("payloadIn to tun error:", err)
			return
		}

		putPayloadBuffer(pl)
	}
}

// dynamicSplitRoutes observes DNS answers and installs include/exclude
// /32 routes for resolved A records once per queried domain.
func dynamicSplitRoutes(ctx *vpncore.VPNContext, data []byte, cSess *session.ConnSession) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		query := string(dns.Questions[0].Name)

		if utils.InArrayGeneric(cSess.DynamicSplitIncludeDomains, query) {
			if _, ok := cSess.DynamicSplitIncludeResolved.Load(query); !ok && dns.ANCount > 0 {
				var answers []string
				for _, v := range dns.Answers {
					if v.Type == layers.DNSTypeA {
						answers = append(answers, v.IP.String())
					}
				}
				if len(answers) > 0 {
					cSess.DynamicSplitIncludeResolved.Store(query, answers)
					vpnc.DynamicAddIncludeRoutes(ctx, answers)
				}
			}
		} else if utils.InArrayGeneric(cSess.DynamicSplitExcludeDomains, query) {
			if _, ok := cSess.DynamicSplitExcludeResolved.Load(query); !ok && dns.ANCount > 0 {
				var answers []string
				for _, v := range dns.Answers {
					if v.Type == layers.DNSTypeA {
						answers = append(answers, v.IP.String())
					}
				}
				if len(answers) > 0 {
					cSess.DynamicSplitExcludeResolved.Store(query, answers)
					vpnc.DynamicAddExcludeRoutes(ctx, answers)
				}
			}
		}
	}
}
