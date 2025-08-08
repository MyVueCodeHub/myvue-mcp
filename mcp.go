// Package mcp provides a framework for building Model Context Protocol servers with HTTP transport
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ----------------------------- Core Types ----------------------------------

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("RPC Error %d: %s (data: %v)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("RPC Error %d: %s", e.Code, e.Message)
}

// ----------------------------- MCP Types -----------------------------------

type InitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    ClientCapabilities     `json:"capabilities"`
	ClientInfo      ClientInfo             `json:"clientInfo"`
	InitOptions     map[string]interface{} `json:"initializationOptions,omitempty"`
}

type ClientCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ----------------------------- Tool/Resource/Prompt -------------------------

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema InputSchema `json:"inputSchema"`
	handler     ToolHandler
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
	Raw        json.RawMessage     `json:"-"`
}

type Property struct {
	Type        string        `json:"type"`
	Description string        `json:"description,omitempty"`
	Default     interface{}   `json:"default,omitempty"`
	Enum        []interface{} `json:"enum,omitempty"`
}

func (i InputSchema) MarshalJSON() ([]byte, error) {
	if i.Raw != nil {
		return i.Raw, nil
	}
	type Alias InputSchema
	return json.Marshal(Alias(i))
}

type ToolHandler func(ctx context.Context, args map[string]interface{}) (*ToolResult, error)

type ToolResult struct {
	Content []Content `json:"content"`
}

type Content struct {
	Type     string      `json:"type"`
	Text     string      `json:"text,omitempty"`
	Data     interface{} `json:"data,omitempty"`
	MimeType string      `json:"mimeType,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
	handler     ResourceHandler
}

type ResourceHandler func(ctx context.Context, uri string) (*ResourceContent, error)

type ResourceContent struct {
	URI      string    `json:"uri"`
	MimeType string    `json:"mimeType,omitempty"`
	Content  []Content `json:"contents"`
}

type Prompt struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Arguments   []PromptArg `json:"arguments,omitempty"`
	handler     PromptHandler
}

type PromptArg struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type PromptHandler func(ctx context.Context, args map[string]string) (*PromptResult, error)

type PromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type PromptMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// ----------------------------- Auth & Whitelist ----------------------------

type AuthProvider interface {
	Authenticate(r *http.Request) (bool, error)
	GetPrincipal(r *http.Request) (string, error)
}

type URLWhitelist struct {
	allowedOrigins  map[string]bool
	allowedPatterns []string
	mu              sync.RWMutex
}

func NewURLWhitelist() *URLWhitelist {
	return &URLWhitelist{
		allowedOrigins:  make(map[string]bool),
		allowedPatterns: []string{},
	}
}

func (w *URLWhitelist) AddOrigin(o string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.allowedOrigins[o] = true
}

func (w *URLWhitelist) IsAllowed(origin string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.allowedOrigins[origin] {
		return true
	}
	for _, p := range w.allowedPatterns {
		if strings.Contains(p, "*") {
			parts := strings.Split(p, "*")
			if len(parts) == 2 && strings.HasPrefix(origin, parts[0]) && strings.HasSuffix(origin, parts[1]) {
				return true
			}
		} else if p == origin {
			return true
		}
	}
	return false
}

// ----------------------------- Server impl --------------------------------

type HTTPServerConfig struct {
	Name            string
	Version         string
	ProtocolVersion string

	Host string
	Port int
	Path string

	TLSCert string
	TLSKey  string

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	EnableCORS       bool
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool

	Logger Logger
}

type Session struct {
	ID        string
	Principal string
	StartTime time.Time
	LastSeen  time.Time
	Data      map[string]interface{}
}

type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

type Middleware func(next HandlerFunc) HandlerFunc
type HandlerFunc func(ctx context.Context, req *JSONRPCRequest) (interface{}, error)

type HTTPServer struct {
	config    HTTPServerConfig
	tools     map[string]*Tool
	resources map[string]*Resource
	prompts   map[string]*Prompt

	mu      sync.RWMutex
	running bool
	server  *http.Server

	authProvider AuthProvider
	whitelist    *URLWhitelist

	onInit     func(*InitializeParams) error
	onShutdown func() error

	middleware []Middleware

	customMux *http.ServeMux
	sessions  map[string]*Session
}

// ----------------------------- Constructor --------------------------------

func NewHTTPServer(config HTTPServerConfig) *HTTPServer {
	if config.ProtocolVersion == "" {
		config.ProtocolVersion = "2025-06-18"
	}
	if config.Path == "" {
		config.Path = "/mcp"
	}
	if config.Port == 0 {
		config.Port = 3000
	}
	if config.Logger == nil {
		config.Logger = &defaultLogger{}
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}

	return &HTTPServer{
		config:    config,
		tools:     make(map[string]*Tool),
		resources: make(map[string]*Resource),
		prompts:   make(map[string]*Prompt),
		sessions:  make(map[string]*Session),
		customMux: http.NewServeMux(),
		whitelist: NewURLWhitelist(),
	}
}

func (s *HTTPServer) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	s.customMux.HandleFunc(pattern, handler)
}

func (s *HTTPServer) Handle(pattern string, handler http.Handler) {
	s.customMux.Handle(pattern, handler)
}

func (s *HTTPServer) SetAuthProvider(provider AuthProvider) {
	s.authProvider = provider
}

func (s *HTTPServer) SetURLWhitelist(w *URLWhitelist) {
	s.whitelist = w
}

func (s *HTTPServer) Use(m Middleware) {
	s.middleware = append(s.middleware, m)
}

func (s *HTTPServer) OnInitialize(h func(*InitializeParams) error) {
	s.onInit = h
}

func (s *HTTPServer) OnShutdown(h func() error) {
	s.onShutdown = h
}

// ----------------------------- Default logger ------------------------------

type defaultLogger struct{}

func (l *defaultLogger) Debug(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "DEBUG: %s %v\n", msg, args)
}
func (l *defaultLogger) Info(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "INFO: %s %v\n", msg, args)
}
func (l *defaultLogger) Error(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: %s %v\n", msg, args)
}

// ----------------------------- HTTP runtime --------------------------------

func (s *HTTPServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Ensure MCP endpoint and helpers are always mounted on the server mux
	s.customMux.HandleFunc(s.config.Path, s.handleHTTPRequest)
	s.customMux.HandleFunc(s.config.Path+"/sse", s.handleSSE)
	s.customMux.HandleFunc("/health", s.handleHealth)

	var handler http.Handler = s.customMux
	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	s.config.Logger.Info("HTTP MCP Server started", "address", addr, "path", s.config.Path)

	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return s.server.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return s.server.ListenAndServe()
}

func (s *HTTPServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return fmt.Errorf("server not running")
	}
	s.running = false
	if s.onShutdown != nil {
		if err := s.onShutdown(); err != nil {
			s.config.Logger.Error("Shutdown hook failed", "error", err)
		}
	}
	return s.server.Shutdown(ctx)
}

// ----------------------------- CORS / Helpers -------------------------------

func (s *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic permissive CORS for browser clients (Claude Web). Adjust for security.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if len(s.config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(s.config.AllowedMethods, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		}

		if len(s.config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.AllowedHeaders, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
		}

		if s.config.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == http.MethodOptions {
			// Per spec: preflight returns minimal/no body; 204 is fine.
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Validator for MCP-Protocol-Version header (basic)
var supportedProtocolVersions = []string{
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

func isProtocolSupported(v string) bool {
	if v == "" {
		return true // default assumption
	}
	for _, s := range supportedProtocolVersions {
		if v == s {
			return true
		}
	}
	return false
}

// ----------------------------- HTTP handlers -------------------------------

func (s *HTTPServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Always set CORS headers locally too (defense in depth)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if len(s.config.AllowedHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.AllowedHeaders, ", "))
	} else {
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
	}

	// Protocol version header validation
	clientProto := r.Header.Get("MCP-Protocol-Version")
	if !isProtocolSupported(clientProto) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Unsupported MCP-Protocol-Version: %s", clientProto),
		})
		return
	}

	accept := r.Header.Get("Accept")
	acceptES := strings.Contains(accept, "text/event-stream")

	// OPTIONS preflight (some clients may still call directly)
	if r.Method == http.MethodOptions {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// GET - used by clients to open SSE streams. We do not implement SSE here,
	// so per spec we must either return text/event-stream or 405 Method Not Allowed.
	if r.Method == http.MethodGet {
		// Client asked for SSE -> we don't support SSE in this implementation
		if acceptES {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "SSE not supported on this server",
			})
			return
		}
		// If client asked for JSON or did not specify, return a small JSON health/info
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mcp":    "ready",
			"server": map[string]string{"name": s.config.Name, "version": s.config.Version},
		})
		return
	}

	// POST - messages from client
	if r.Method != http.MethodPost {
		// For any other methods return JSON error (no text/plain)
		w.Header().Set("Allow", "POST, OPTIONS")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code":    -32600,
				"message": "Only POST supported on this endpoint",
			},
		})
		return
	}

	// Authentication check (if configured). AuthProvider may allow unauthenticated for some paths.
	if s.authProvider != nil {
		ok, err := s.authProvider.Authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32603,
					"message": "Authentication error",
				},
			})
			return
		}
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32600,
					"message": "Unauthorized",
				},
			})
			return
		}
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.config.Logger.Error("Failed to read request body", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Batch vs single detection
	bodyTrim := strings.TrimSpace(string(body))
	if bodyTrim == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "Empty request body"})
		return
	}

	if strings.HasPrefix(bodyTrim, "[") {
		// Batch
		var requests []JSONRPCRequest
		if err := json.Unmarshal(body, &requests); err != nil {
			s.sendHTTPError(w, nil, -32700, "Parse error", nil)
			return
		}

		// Collect responses only for entries that have an ID
		responses := make([]JSONRPCResponse, 0, len(requests))
		for _, req := range requests {
			// Notifications (no ID) must not get a response
			if req.ID == nil {
				// handle notification (process but no reply)
				ctx := r.Context()
				if s.authProvider != nil {
					if principal, err := s.authProvider.GetPrincipal(r); err == nil {
						ctx = context.WithValue(ctx, "principal", principal)
					}
				}
				_, _ = s.handleRequest(ctx, &req) // ignore result
				continue
			}

			ctx := r.Context()
			if s.authProvider != nil {
				if principal, err := s.authProvider.GetPrincipal(r); err == nil {
					ctx = context.WithValue(ctx, "principal", principal)
				}
			}

			result, rpcErr := s.handleRequest(ctx, &req)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			if rpcErr != nil {
				resp.Error = rpcErr
			} else {
				resp.Result = result
			}
			responses = append(responses, resp)
		}

		if len(responses) == 0 {
			// Batch with only notifications -> 202 Accepted and no body
			w.WriteHeader(http.StatusAccepted)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses)
		return
	}

	// Single request
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.sendHTTPError(w, nil, -32700, "Parse error", nil)
		return
	}

	// Notifications: return 202 Accepted with no body
	if req.ID == nil {
		// Process notification asynchronously (or synchronously here), but return 202
		ctx := r.Context()
		if s.authProvider != nil {
			if principal, err := s.authProvider.GetPrincipal(r); err == nil {
				ctx = context.WithValue(ctx, "principal", principal)
			}
		}
		_, _ = s.handleRequest(ctx, &req) // ignore result for notifications
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Normal request -> produce JSON response
	ctx := r.Context()
	if s.authProvider != nil {
		if principal, err := s.authProvider.GetPrincipal(r); err == nil {
			ctx = context.WithValue(ctx, "principal", principal)
		}
	}

	result, rpcErr := s.handleRequest(ctx, &req)
	resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}

	// If client asked for event-stream and SSE were supported we could open SSE.
	// This implementation returns JSON instead (clients MUST accept application/json).
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleBatchRequest left for compatibility, but main batching logic is in handleHTTPRequest
func (s *HTTPServer) handleBatchRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	// kept for backward compatibility in case other call sites use it
	s.handleHTTPRequest(w, r)
}

func (s *HTTPServer) handleRequest(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	handler := s.getHandler(req.Method)
	for i := len(s.middleware) - 1; i >= 0; i-- {
		handler = s.middleware[i](handler)
	}
	result, err := handler(ctx, req)
	if err != nil {
		if rpcErr, ok := err.(*RPCError); ok {
			return nil, rpcErr
		}
		return nil, &RPCError{Code: -32603, Message: err.Error()}
	}
	return result, nil
}

func (s *HTTPServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	// SSE not implemented in this file. Per spec, returning 405 is valid.
	w.Header().Set("Allow", "POST, OPTIONS")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "SSE not implemented",
	})
}

func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status": "healthy",
		"server": map[string]interface{}{
			"name":    s.config.Name,
			"version": s.config.Version,
		},
		"capabilities": map[string]interface{}{
			"tools":     len(s.tools),
			"resources": len(s.resources),
			"prompts":   len(s.prompts),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *HTTPServer) sendHTTPError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ----------------------------- Request handlers ----------------------------

func (s *HTTPServer) getHandler(method string) HandlerFunc {
	switch method {
	case "initialize":
		return s.handleInitialize
	case "tools/list":
		return s.handleToolsList
	case "tools/call":
		return s.handleToolCall
	case "resources/list":
		return s.handleResourcesList
	case "resources/read":
		return s.handleResourceRead
	case "prompts/list":
		return s.handlePromptsList
	case "prompts/get":
		return s.handlePromptGet
	default:
		return func(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
			return nil, &RPCError{Code: -32601, Message: "Method not found"}
		}
	}
}

func (s *HTTPServer) handleInitialize(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params InitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}
	if s.onInit != nil {
		if err := s.onInit(&params); err != nil {
			return nil, err
		}
	}
	capabilities := map[string]interface{}{}
	if len(s.tools) > 0 {
		capabilities["tools"] = map[string]interface{}{}
	}
	if len(s.resources) > 0 {
		capabilities["resources"] = map[string]interface{}{}
	}
	if len(s.prompts) > 0 {
		capabilities["prompts"] = map[string]interface{}{}
	}
	// Optionally set server-sent session header on initialize (not implemented here)
	return map[string]interface{}{
		"protocolVersion": s.config.ProtocolVersion,
		"capabilities":    capabilities,
		"serverInfo": map[string]interface{}{
			"name":    s.config.Name,
			"version": s.config.Version,
		},
	}, nil
}

func (s *HTTPServer) handleToolsList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tools := make([]map[string]interface{}, 0, len(s.tools))
	for _, tool := range s.tools {
		tools = append(tools, map[string]interface{}{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": tool.InputSchema,
		})
	}
	return map[string]interface{}{"tools": tools}, nil
}

func (s *HTTPServer) handleToolCall(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}
	s.mu.RLock()
	tool, exists := s.tools[params.Name]
	s.mu.RUnlock()
	if !exists {
		return nil, &RPCError{Code: -32602, Message: fmt.Sprintf("Unknown tool: %s", params.Name)}
	}
	result, err := tool.handler(ctx, params.Arguments)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *HTTPServer) handleResourcesList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	resources := make([]map[string]interface{}, 0, len(s.resources))
	for _, resource := range s.resources {
		resources = append(resources, map[string]interface{}{
			"uri":         resource.URI,
			"name":        resource.Name,
			"description": resource.Description,
			"mimeType":    resource.MimeType,
		})
	}
	return map[string]interface{}{"resources": resources}, nil
}

func (s *HTTPServer) handleResourceRead(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}
	s.mu.RLock()
	resource, exists := s.resources[params.URI]
	s.mu.RUnlock()
	if !exists {
		return nil, &RPCError{Code: -32602, Message: fmt.Sprintf("Unknown resource: %s", params.URI)}
	}
	content, err := resource.handler(ctx, params.URI)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (s *HTTPServer) handlePromptsList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prompts := make([]map[string]interface{}, 0, len(s.prompts))
	for _, prompt := range s.prompts {
		prompts = append(prompts, map[string]interface{}{
			"name":        prompt.Name,
			"description": prompt.Description,
			"arguments":   prompt.Arguments,
		})
	}
	return map[string]interface{}{"prompts": prompts}, nil
}

func (s *HTTPServer) handlePromptGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}
	s.mu.RLock()
	prompt, exists := s.prompts[params.Name]
	s.mu.RUnlock()
	if !exists {
		return nil, &RPCError{Code: -32602, Message: fmt.Sprintf("Unknown prompt: %s", params.Name)}
	}
	result, err := prompt.handler(ctx, params.Arguments)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *HTTPServer) EnableRESTAPI(enable bool) {
	if !enable {
		return
	}
	// List all tools
	s.customMux.HandleFunc("/api/tools", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		tools := make([]map[string]interface{}, 0, len(s.tools))
		for name, tool := range s.tools {
			tools = append(tools, map[string]interface{}{
				"name":        name,
				"description": tool.Description,
				"inputSchema": tool.InputSchema,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tools": tools,
		})
	})

	// Run a tool
	s.customMux.HandleFunc("/api/tool/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		toolName := strings.TrimPrefix(r.URL.Path, "/api/tool/")
		tool, ok := s.tools[toolName]
		if !ok {
			http.Error(w, "Tool not found", http.StatusNotFound)
			return
		}

		// Parse JSON body into params map
		var params map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		// Run the tool handler directly
		result, err := tool.handler(r.Context(), params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": result,
		})
	})
}

// RegisterTool registers a tool with full control over the input schema
func (s *HTTPServer) RegisterTool(name, description string, schema InputSchema, handler ToolHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tools[name]; exists {
		return fmt.Errorf("tool %s already registered", name)
	}

	s.tools[name] = &Tool{
		Name:        name,
		Description: description,
		InputSchema: schema,
		handler:     handler,
	}

	s.config.Logger.Info("Tool registered", "name", name)
	return nil
}

// RegisterSimpleTool registers a tool with a simple handler (no input schema validation)
func (s *HTTPServer) RegisterSimpleTool(name, description string, handler ToolHandler) error {
	// Create a simple schema that accepts any object
	schema := InputSchema{
		Type:       "object",
		Properties: map[string]Property{},
	}

	return s.RegisterTool(name, description, schema, handler)
}

// RegisterResource registers a resource handler
func (s *HTTPServer) RegisterResource(uri, name, description, mimeType string, handler ResourceHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.resources[uri]; exists {
		return fmt.Errorf("resource %s already registered", uri)
	}

	s.resources[uri] = &Resource{
		URI:         uri,
		Name:        name,
		Description: description,
		MimeType:    mimeType,
		handler:     handler,
	}

	s.config.Logger.Info("Resource registered", "uri", uri)
	return nil
}

// RegisterPrompt registers a prompt handler
func (s *HTTPServer) RegisterPrompt(name, description string, args []PromptArg, handler PromptHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.prompts[name]; exists {
		return fmt.Errorf("prompt %s already registered", name)
	}

	s.prompts[name] = &Prompt{
		Name:        name,
		Description: description,
		Arguments:   args,
		handler:     handler,
	}

	s.config.Logger.Info("Prompt registered", "name", name)
	return nil
}

// UnregisterTool removes a tool from the server
func (s *HTTPServer) UnregisterTool(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tools[name]; !exists {
		return fmt.Errorf("tool %s not found", name)
	}

	delete(s.tools, name)
	s.config.Logger.Info("Tool unregistered", "name", name)
	return nil
}

// UnregisterResource removes a resource from the server
func (s *HTTPServer) UnregisterResource(uri string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.resources[uri]; !exists {
		return fmt.Errorf("resource %s not found", uri)
	}

	delete(s.resources, uri)
	s.config.Logger.Info("Resource unregistered", "uri", uri)
	return nil
}

// UnregisterPrompt removes a prompt from the server
func (s *HTTPServer) UnregisterPrompt(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.prompts[name]; !exists {
		return fmt.Errorf("prompt %s not found", name)
	}

	delete(s.prompts, name)
	s.config.Logger.Info("Prompt unregistered", "name", name)
	return nil
}

// GetTools returns a list of registered tool names
func (s *HTTPServer) GetTools() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.tools))
	for name := range s.tools {
		names = append(names, name)
	}
	return names
}

// GetResources returns a list of registered resource URIs
func (s *HTTPServer) GetResources() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uris := make([]string, 0, len(s.resources))
	for uri := range s.resources {
		uris = append(uris, uri)
	}
	return uris
}

// GetPrompts returns a list of registered prompt names
func (s *HTTPServer) GetPrompts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.prompts))
	for name := range s.prompts {
		names = append(names, name)
	}
	return names
}

// ----------------------------- Convenience ---------------------------------

func TextContent(text string) Content {
	return Content{Type: "text", Text: text}
}
func ImageContent(data string, mimeType string) Content {
	return Content{Type: "image", Data: data, MimeType: mimeType}
}
func ErrorResponse(code int, message string) error {
	return &RPCError{Code: code, Message: message}
}
