package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/sourcegraph/jsonrpc2"
	ws "github.com/sourcegraph/jsonrpc2/websocket"
	"tuncat/internal/engine"
	engineconfig "tuncat/internal/engine/config"
)

const (
	STATUS = iota
	CONFIG
	CONNECT
	DISCONNECT
	RECONNECT
	INTERFACE
	ABORT
	STAT
)

type RPCServer struct {
	mu              sync.Mutex
	clients         []*jsonrpc2.Conn
	connectedStr    string
	disconnectedStr string
	ctx             *engine.Context
	httpServer      *http.Server
}

func NewRPCServer(ctx *engine.Context) *RPCServer {
	if err := ensureContext(ctx); err != nil {
		ctx = engine.NewContext()
		_ = ensureContext(ctx)
	}
	return &RPCServer{
		ctx:             ctx,
		disconnectedStr: "disconnected",
	}
}

func (server *RPCServer) Context() *engine.Context {
	return server.ctx
}

func (server *RPCServer) Setup() error {
	if err := ensureContext(server.ctx); err != nil {
		return err
	}

	addr, err := normalizeRPCAddr(server.ctx.Cfg.RPCAddr)
	if err != nil {
		return err
	}
	if addr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", server.rpc)

	server.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		err := server.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			engineconfig.Error("rpc listen failed:", err)
		}
	}()

	engineconfig.Info("rpc server listening on", addr)
	return nil
}

func (server *RPCServer) Shutdown(ctx context.Context) error {
	if server.httpServer == nil {
		return nil
	}
	return server.httpServer.Shutdown(ctx)
}

func (server *RPCServer) addClient(conn *jsonrpc2.Conn) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.clients = append(server.clients, conn)
}

func (server *RPCServer) removeClient(conn *jsonrpc2.Conn) {
	server.mu.Lock()
	defer server.mu.Unlock()
	for i, c := range server.clients {
		if c == conn {
			server.clients = append(server.clients[:i], server.clients[i+1:]...)
			engineconfig.Debug(fmt.Sprintf("client %d disconnected", i))
			break
		}
	}
}

func (server *RPCServer) clientSnapshot() []*jsonrpc2.Conn {
	server.mu.Lock()
	defer server.mu.Unlock()
	clients := make([]*jsonrpc2.Conn, len(server.clients))
	copy(clients, server.clients)
	return clients
}

func (server *RPCServer) rpc(resp http.ResponseWriter, req *http.Request) {
	up := websocket.Upgrader{
		CheckOrigin: isAllowedRPCOrigin,
	}
	conn, err := up.Upgrade(resp, req, nil)
	if err != nil {
		engineconfig.Error(err)
		return
	}
	defer conn.Close()

	jsonStream := ws.NewObjectStream(conn)
	rpcConn := jsonrpc2.NewConn(req.Context(), jsonStream, server, jsonrpc2.SetLogger(engineconfig.GetBaseLogger()))
	server.addClient(rpcConn)
	<-rpcConn.DisconnectNotify()
	server.removeClient(rpcConn)
}

func (server *RPCServer) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	defer func() {
		if err := recover(); err != nil {
			engineconfig.Error(string(debug.Stack()))
		}
	}()

	session := server.ctx.Session
	cfg := server.ctx.Cfg
	profile := server.ctx.Profile

	switch req.ID.Num {
	case STAT:
		if session.CSess != nil {
			_ = conn.Reply(ctx, req.ID, session.CSess.Stat)
			return
		}
		jError := jsonrpc2.Error{Code: 1, Message: server.disconnectedStr}
		_ = conn.ReplyWithError(ctx, req.ID, &jError)
	case STATUS:
		if session.CSess != nil {
			if !cfg.NoDTLS && session.CSess.DTLSPort != "" {
				<-session.CSess.DtlsSetupChan
			}

			if session.CSess != nil {
				_ = conn.Reply(ctx, req.ID, session.CSess)
				return
			}
		}

		jError := jsonrpc2.Error{Code: 1, Message: server.disconnectedStr}
		_ = conn.ReplyWithError(ctx, req.ID, &jError)
	case CONNECT:
		if session.CSess != nil {
			_ = conn.Reply(ctx, req.ID, server.connectedStr)
			return
		}
		err := json.Unmarshal(*req.Params, profile)
		if err != nil {
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		err = server.Connect()
		if err != nil {
			engineconfig.Error(err)
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			server.DisConnect()
			return
		}
		server.connectedStr = "connected to " + profile.Host
		server.disconnectedStr = "disconnected from " + profile.Host
		_ = conn.Reply(ctx, req.ID, server.connectedStr)
		go server.monitor()
	case RECONNECT:
		if session.CSess != nil {
			_ = conn.Reply(ctx, req.ID, server.connectedStr)
			return
		}
		err := server.SetupTunnel(true)
		if err != nil {
			engineconfig.Error(err)
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			server.DisConnect()
			return
		}
		_ = conn.Reply(ctx, req.ID, server.connectedStr)
		go server.monitor()
	case DISCONNECT:
		if session.CSess != nil {
			server.DisConnect()
			_ = conn.Reply(ctx, req.ID, server.disconnectedStr)
		} else {
			jError := jsonrpc2.Error{Code: 1, Message: server.disconnectedStr}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
		}
	case CONFIG:
		err := json.Unmarshal(*req.Params, server.ctx.Cfg)
		if err != nil {
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		server.ctx.Logger = engineconfig.InitLog(server.ctx.Cfg)
		_ = conn.Reply(ctx, req.ID, "ready to connect")
	case INTERFACE:
		err := json.Unmarshal(*req.Params, server.ctx.LocalInterface)
		if err != nil {
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		server.ctx.Profile.Initialized = true
		_ = conn.Reply(ctx, req.ID, "ready to connect")
	default:
		engineconfig.Debug("receive rpc call:", req)
		jError := jsonrpc2.Error{Code: 1, Message: "unknown method: " + req.Method}
		_ = conn.ReplyWithError(ctx, req.ID, &jError)
	}
}

func (server *RPCServer) monitor() {
	if server.ctx.Session.CloseChan == nil {
		return
	}
	<-server.ctx.Session.CloseChan
	ctx := context.Background()
	for _, conn := range server.clientSnapshot() {
		if server.ctx.Session.ActiveClose {
			_ = conn.Reply(ctx, jsonrpc2.ID{Num: DISCONNECT, IsString: false}, server.disconnectedStr)
		} else {
			_ = conn.Reply(ctx, jsonrpc2.ID{Num: ABORT, IsString: false}, server.disconnectedStr)
		}
	}
}

func (server *RPCServer) Connect() error {
	return Connect(server.ctx)
}

func (server *RPCServer) SetupTunnel(reconnect bool) error {
	return SetupTunnel(reconnect, server.ctx)
}

func (server *RPCServer) DisConnect() {
	DisConnect(server.ctx)
}

func isAllowedRPCOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(strings.ToLower(host), "[]"))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeRPCAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", nil
	}

	if _, err := strconv.Atoi(addr); err == nil {
		addr = "127.0.0.1:" + addr
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("rpc_addr must be localhost/loopback, got %q", host)
	}
	if port == "" {
		return "", fmt.Errorf("rpc_addr port is empty")
	}
	return net.JoinHostPort(host, port), nil
}
