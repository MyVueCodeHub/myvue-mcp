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

// ============================================================================
// Core Protocol Types
// ============================================================================

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

// Error implements the error interface for RPCError
func (e *RPCError) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("RPC Error %d: %s (data: %v)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("RPC Error %d: %s", e.Code, e.Message)
}

// ============================================================================
// MCP Types
// ============================================================================

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

// ============================================================================
// Tool System
// ============================================================================

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

// ============================================================================
// Resource System
// ============================================================================

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

// ============================================================================
// Prompt System
// ============================================================================

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

// ============================================================================
// Authentication System
// ============================================================================

// AuthProvider defines the interface for authentication
type AuthProvider interface {
	// Authenticate validates the request and returns whether it's authorized
	Authenticate(r *http.Request) (bool, error)
	// GetPrincipal returns the authenticated principal (user/client) if any
	GetPrincipal(r *http.Request) (string, error)
}

// TokenAuthProvider implements token-based authentication
type TokenAuthProvider struct {
	tokens map[string]string // token -> principal mapping
	mu     sync.RWMutex
}

func NewTokenAuthProvider() *TokenAuthProvider {
	return &TokenAuthProvider{
		tokens: make(map[string]string),
	}
}

func (t *TokenAuthProvider) AddToken(token, principal string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens[token] = principal
}

func (t *TokenAuthProvider) RemoveToken(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tokens, token)
}

func (t *TokenAuthProvider) Authenticate(r *http.Request) (bool, error) {
	token := t.extractToken(r)
	if token == "" {
		return false, nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	_, exists := t.tokens[token]
	return exists, nil
}

func (t *TokenAuthProvider) GetPrincipal(r *http.Request) (string, error) {
	token := t.extractToken(r)
	if token == "" {
		return "", fmt.Errorf("no token found")
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	principal, exists := t.tokens[token]
	if !exists {
		return "", fmt.Errorf("invalid token")
	}
	return principal, nil
}

func (t *TokenAuthProvider) extractToken(r *http.Request) string {
	// Check Authorization header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check query parameter as fallback
	return r.URL.Query().Get("token")
}

// APIKeyAuthProvider implements API key authentication
type APIKeyAuthProvider struct {
	apiKeys map[string]string // apiKey -> principal mapping
	header  string            // header name to check (default: X-API-Key)
	mu      sync.RWMutex
}

func NewAPIKeyAuthProvider(headerName string) *APIKeyAuthProvider {
	if headerName == "" {
		headerName = "X-API-Key"
	}
	return &APIKeyAuthProvider{
		apiKeys: make(map[string]string),
		header:  headerName,
	}
}

func (a *APIKeyAuthProvider) AddAPIKey(key, principal string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiKeys[key] = principal
}

func (a *APIKeyAuthProvider) Authenticate(r *http.Request) (bool, error) {
	key := r.Header.Get(a.header)
	if key == "" {
		return false, nil
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	_, exists := a.apiKeys[key]
	return exists, nil
}

func (a *APIKeyAuthProvider) GetPrincipal(r *http.Request) (string, error) {
	key := r.Header.Get(a.header)
	if key == "" {
		return "", fmt.Errorf("no API key found")
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	principal, exists := a.apiKeys[key]
	if !exists {
		return "", fmt.Errorf("invalid API key")
	}
	return principal, nil
}

// ============================================================================
// URL Whitelist
// ============================================================================

// URLWhitelist manages allowed origins and referers
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

func (w *URLWhitelist) AddOrigin(origin string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.allowedOrigins[origin] = true
}

func (w *URLWhitelist) AddPattern(pattern string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.allowedPatterns = append(w.allowedPatterns, pattern)
}

func (w *URLWhitelist) IsAllowed(origin string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Check exact match
	if w.allowedOrigins[origin] {
		return true
	}

	// Check patterns
	for _, pattern := range w.allowedPatterns {
		if matched := matchPattern(pattern, origin); matched {
			return true
		}
	}

	return false
}

func matchPattern(pattern, origin string) bool {
	// Simple wildcard matching (e.g., "https://*.claude.ai")
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(origin, parts[0]) && strings.HasSuffix(origin, parts[1])
		}
	}
	return pattern == origin
}

// ============================================================================
// HTTP Server Implementation
// ============================================================================

// HTTPServerConfig holds HTTP server configuration
type HTTPServerConfig struct {
	Name            string
	Version         string
	ProtocolVersion string

	// HTTP settings
	Host string
	Port int
	Path string // Base path for MCP endpoints (default: "/mcp")

	// TLS settings
	TLSCert string
	TLSKey  string

	// Timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// CORS settings
	EnableCORS       bool
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool

	// Logging
	Logger Logger
}

// Session represents a client session
type Session struct {
	ID        string
	Principal string
	StartTime time.Time
	LastSeen  time.Time
	Data      map[string]interface{}
}

// Logger interface for custom logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// Middleware allows request/response interception
type Middleware func(next HandlerFunc) HandlerFunc

type HandlerFunc func(ctx context.Context, req *JSONRPCRequest) (interface{}, error)

// HTTPServer represents an HTTP-based MCP server
type HTTPServer struct {
	config    HTTPServerConfig
	tools     map[string]*Tool
	resources map[string]*Resource
	prompts   map[string]*Prompt

	mu      sync.RWMutex
	running bool
	server  *http.Server

	// Authentication
	authProvider AuthProvider
	whitelist    *URLWhitelist

	// Hooks for lifecycle events
	onInit     func(*InitializeParams) error
	onShutdown func() error

	// Middleware
	middleware []Middleware

	// Session management
	sessions map[string]*Session
	sessmu   sync.RWMutex

	// Custom route handlers - NEW FIELD
	customHandlers map[string]http.HandlerFunc
	customMux      *http.ServeMux
}

// NewHTTPServer creates a new HTTP-based MCP server
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
		config:         config,
		tools:          make(map[string]*Tool),
		resources:      make(map[string]*Resource),
		prompts:        make(map[string]*Prompt),
		sessions:       make(map[string]*Session),
		whitelist:      NewURLWhitelist(),
		customHandlers: make(map[string]http.HandlerFunc), // NEW
		customMux:      http.NewServeMux(),                // NEW
	}
}

// HandleFunc registers a custom HTTP handler for a specific path - NEW METHOD
func (s *HTTPServer) HandleFunc(pattern string, handler http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customHandlers[pattern] = handler
	s.customMux.HandleFunc(pattern, handler)
}

// Handle registers a custom HTTP handler for a specific path - NEW METHOD
func (s *HTTPServer) Handle(pattern string, handler http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customMux.Handle(pattern, handler)
}

// Start begins the HTTP server (UPDATED)
func (s *HTTPServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Create the main mux that will route requests
	mainMux := http.NewServeMux()

	// Register custom handlers first (they take priority)
	for pattern, handler := range s.customHandlers {
		mainMux.HandleFunc(pattern, handler)
	}

	// Register MCP endpoint
	mainMux.HandleFunc(s.config.Path, s.handleHTTPRequest)

	// Register SSE endpoint for server-sent events (if needed)
	mainMux.HandleFunc(s.config.Path+"/sse", s.handleSSE)

	// Health check endpoint
	mainMux.HandleFunc("/health", s.handleHealth)

	// Wrap with CORS if enabled
	var handler http.Handler = mainMux
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

	var err error
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		err = s.server.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	} else {
		err = s.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// GetMux returns the internal ServeMux for advanced routing needs - NEW METHOD
func (s *HTTPServer) GetMux() *http.ServeMux {
	return s.customMux
}

// SetAuthProvider sets the authentication provider
func (s *HTTPServer) SetAuthProvider(provider AuthProvider) {
	s.authProvider = provider
}

// SetURLWhitelist sets the URL whitelist
func (s *HTTPServer) SetURLWhitelist(whitelist *URLWhitelist) {
	s.whitelist = whitelist
}

// ============================================================================
// Registration Methods (same as before)
// ============================================================================

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

	return nil
}

func (s *HTTPServer) RegisterSimpleTool(name, description string, handler ToolHandler) error {
	schema := InputSchema{
		Type:       "object",
		Properties: map[string]Property{},
	}
	return s.RegisterTool(name, description, schema, handler)
}

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

	return nil
}

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

	return nil
}

func (s *HTTPServer) Use(m Middleware) {
	s.middleware = append(s.middleware, m)
}

func (s *HTTPServer) OnInitialize(handler func(*InitializeParams) error) {
	s.onInit = handler
}

func (s *HTTPServer) OnShutdown(handler func() error) {
	s.onShutdown = handler
}

// ============================================================================
// HTTP Server Runtime
// ============================================================================

// Stop gracefully shuts down the server
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

// ============================================================================
// HTTP Request Handling
// ============================================================================

// --- MCP HTTP request handler ---
func (s *HTTPServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Auth check
	if s.authProvider != nil {
		authenticated, err := s.authProvider.Authenticate(r)
		if err != nil {
			s.config.Logger.Error("Authentication error", "error", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32603,
					"message": "Authentication error",
				},
			})
			return
		}
		if !authenticated {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32600,
					"message": "Unauthorized",
				},
			})
			return
		}
	}

	// OPTIONS preflight
	if r.Method == "OPTIONS" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	// Non-POST requests → JSON error, not plain text
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"error": map[string]interface{}{
				"code":    -32600,
				"message": "Only POST supported on this endpoint",
			},
		})
		return
	}

	// Parse body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.config.Logger.Error("Failed to read request body", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Batch requests
	if len(body) > 0 && body[0] == '[' {
		s.handleBatchRequest(w, r, body)
		return
	}

	// Single request
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.config.Logger.Error("Failed to parse request", "error", err)
		s.sendHTTPError(w, nil, -32700, "Parse error", nil)
		return
	}

	// Notifications (no ID)
	if req.ID == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx := r.Context()
	if s.authProvider != nil {
		if principal, err := s.authProvider.GetPrincipal(r); err == nil {
			ctx = context.WithValue(ctx, "principal", principal)
		}
	}

	result, rpcErr := s.handleRequest(ctx, &req)

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPServer) handleBatchRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var requests []JSONRPCRequest
	if err := json.Unmarshal(body, &requests); err != nil {
		s.sendHTTPError(w, nil, -32700, "Parse error", nil)
		return
	}

	responses := make([]JSONRPCResponse, 0, len(requests))
	ctx := r.Context()

	for _, req := range requests {
		result, rpcErr := s.handleRequest(ctx, &req)
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
		}
		if rpcErr != nil {
			resp.Error = rpcErr
		} else {
			resp.Result = result
		}
		responses = append(responses, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responses)
}

func (s *HTTPServer) handleRequest(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	handler := s.getHandler(req.Method)

	// Apply middleware
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
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// TODO: Implement SSE for notifications/events
	// This would be used for list_changed events
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
	json.NewEncoder(w).Encode(status)
}

func (s *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		if len(s.config.AllowedOrigins) > 0 {
			origin := r.Header.Get("Origin")
			for _, allowed := range s.config.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		if len(s.config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(s.config.AllowedMethods, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		}

		if len(s.config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.AllowedHeaders, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if s.config.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		next.ServeHTTP(w, r)
	})
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
	json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// Request Handlers (same as before with minor adjustments)
// ============================================================================

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

// ============================================================================
// Helper Types
// ============================================================================

type defaultLogger struct{}

func (l *defaultLogger) Debug(msg string, args ...interface{}) {}
func (l *defaultLogger) Info(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "INFO: %s %v\n", msg, args)
}
func (l *defaultLogger) Error(msg string, args ...interface{}) {
	fmt.Fprintf(io.Discard, "ERROR: %s %v\n", msg, args)
}

// ============================================================================
// Convenience Functions
// ============================================================================

func TextContent(text string) Content {
	return Content{Type: "text", Text: text}
}

func ImageContent(data string, mimeType string) Content {
	return Content{Type: "image", Data: data, MimeType: mimeType}
}

func ErrorResponse(code int, message string) error {
	return &RPCError{Code: code, Message: message}
}
