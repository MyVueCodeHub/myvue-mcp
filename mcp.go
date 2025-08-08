// Package mcp provides a comprehensive framework for building Model Context Protocol servers
// with support for STDIO, HTTP, SSE, and REST API transports
package mcp

import (
	"bufio"
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

// ----------------------------- MCP Protocol Types --------------------------

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

// ----------------------------- Tools, Resources, Prompts -------------------

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

// ----------------------------- Authentication ------------------------------

type AuthProvider interface {
	// Authenticate checks if the request is authenticated
	Authenticate(r *http.Request) (bool, error)
	// GetPrincipal returns the authenticated principal/user ID
	GetPrincipal(r *http.Request) (string, error)
}

// NoAuth provider allows all requests
type NoAuth struct{}

func (n *NoAuth) Authenticate(r *http.Request) (bool, error) {
	return true, nil
}

func (n *NoAuth) GetPrincipal(r *http.Request) (string, error) {
	return "anonymous", nil
}

// BearerTokenAuth provides simple bearer token authentication
type BearerTokenAuth struct {
	tokens map[string]string // token -> principal
	mu     sync.RWMutex
}

func NewBearerTokenAuth() *BearerTokenAuth {
	return &BearerTokenAuth{
		tokens: make(map[string]string),
	}
}

func (b *BearerTokenAuth) AddToken(token, principal string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[token] = principal
}

func (b *BearerTokenAuth) RemoveToken(token string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.tokens, token)
}

func (b *BearerTokenAuth) Authenticate(r *http.Request) (bool, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false, nil
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return false, nil
	}

	token := strings.TrimPrefix(auth, "Bearer ")

	b.mu.RLock()
	defer b.mu.RUnlock()

	_, exists := b.tokens[token]
	return exists, nil
}

func (b *BearerTokenAuth) GetPrincipal(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("no authorization header")
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("invalid authorization header")
	}

	token := strings.TrimPrefix(auth, "Bearer ")

	b.mu.RLock()
	defer b.mu.RUnlock()

	principal, exists := b.tokens[token]
	if !exists {
		return "", fmt.Errorf("invalid token")
	}

	return principal, nil
}

// ----------------------------- Logger Interface ----------------------------

type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

type StderrLogger struct{}

func (l *StderrLogger) Debug(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[DEBUG] %s %v\n", msg, args)
}

func (l *StderrLogger) Info(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[INFO] %s %v\n", msg, args)
}

func (l *StderrLogger) Error(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s %v\n", msg, args)
}

// ----------------------------- Server Configuration ------------------------

type ServerConfig struct {
	Name            string
	Version         string
	ProtocolVersion string

	// HTTP Configuration
	Host string
	Port int
	Path string

	// TLS Configuration
	TLSCert string
	TLSKey  string

	// Timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// CORS Configuration
	EnableCORS       bool
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool

	// Features
	EnableSSE     bool // Enable Server-Sent Events
	EnableREST    bool // Enable REST API endpoints
	EnableMetrics bool // Enable metrics endpoint

	// Logging
	Logger Logger
}

// ----------------------------- Universal MCP Server ------------------------

type Server struct {
	config ServerConfig

	tools     map[string]*Tool
	resources map[string]*Resource
	prompts   map[string]*Prompt

	mu      sync.RWMutex
	running bool

	authProvider AuthProvider

	onInit     func(*InitializeParams) error
	onShutdown func() error

	// HTTP server
	httpServer *http.Server
	sseClients map[string]*SSEClient

	// Metrics
	metrics *ServerMetrics
}

type ServerMetrics struct {
	RequestCount  int64
	ErrorCount    int64
	ToolCalls     map[string]int64
	ResourceReads map[string]int64
	PromptsUsed   map[string]int64
	mu            sync.RWMutex
}

type SSEClient struct {
	ID       string
	Events   chan string
	Close    chan bool
	Response http.ResponseWriter
}

// ----------------------------- Constructor ---------------------------------

func NewServer(config ServerConfig) *Server {
	// Set defaults
	if config.ProtocolVersion == "" {
		config.ProtocolVersion = "2024-11-05"
	}
	if config.Path == "" {
		config.Path = "/mcp"
	}
	if config.Port == 0 {
		config.Port = 3000
	}
	if config.Logger == nil {
		config.Logger = &StderrLogger{}
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}

	return &Server{
		config:       config,
		tools:        make(map[string]*Tool),
		resources:    make(map[string]*Resource),
		prompts:      make(map[string]*Prompt),
		sseClients:   make(map[string]*SSEClient),
		authProvider: &NoAuth{},
		metrics: &ServerMetrics{
			ToolCalls:     make(map[string]int64),
			ResourceReads: make(map[string]int64),
			PromptsUsed:   make(map[string]int64),
		},
	}
}

// ----------------------------- Registration Methods ------------------------

func (s *Server) RegisterTool(name, description string, schema InputSchema, handler ToolHandler) error {
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

func (s *Server) RegisterSimpleTool(name, description string, handler ToolHandler) error {
	schema := InputSchema{
		Type:       "object",
		Properties: map[string]Property{},
	}
	return s.RegisterTool(name, description, schema, handler)
}

func (s *Server) RegisterResource(uri, name, description, mimeType string, handler ResourceHandler) error {
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

func (s *Server) RegisterPrompt(name, description string, args []PromptArg, handler PromptHandler) error {
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

// ----------------------------- Lifecycle Methods ---------------------------

func (s *Server) SetAuthProvider(provider AuthProvider) {
	s.authProvider = provider
}

func (s *Server) OnInitialize(handler func(*InitializeParams) error) {
	s.onInit = handler
}

func (s *Server) OnShutdown(handler func() error) {
	s.onShutdown = handler
}

// ----------------------------- Run Methods ---------------------------------

// Run starts the server in the appropriate mode based on environment
func (s *Server) Run() error {
	// Check if we're in a terminal (HTTP mode) or pipe (STDIO mode)
	fileInfo, _ := os.Stdout.Stat()
	if (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		// Terminal detected, run HTTP server
		return s.RunHTTP()
	} else {
		// Pipe detected, run STDIO server
		return s.RunSTDIO()
	}
}

// RunSTDIO starts the server in STDIO mode
func (s *Server) RunSTDIO() error {
	s.config.Logger.Info("Starting MCP server in STDIO mode")

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	decoder := json.NewDecoder(reader)
	encoder := json.NewEncoder(writer)

	for {
		var request JSONRPCRequest

		if err := decoder.Decode(&request); err != nil {
			if err == io.EOF {
				s.config.Logger.Info("Client disconnected")
				break
			}
			s.config.Logger.Error("Error reading request", "error", err)

			// Send parse error
			response := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &RPCError{Code: -32700, Message: "Parse error"},
			}
			encoder.Encode(response)
			writer.Flush()
			continue
		}

		s.config.Logger.Debug("Received request", "method", request.Method, "id", request.ID)

		// Process request
		result, rpcErr := s.handleRequest(context.Background(), &request)

		// Don't send response for notifications (no ID)
		if request.ID == nil {
			continue
		}

		response := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
		}

		if rpcErr != nil {
			response.Error = rpcErr
		} else {
			response.Result = result
		}

		if err := encoder.Encode(response); err != nil {
			s.config.Logger.Error("Error encoding response", "error", err)
		}
		writer.Flush()
	}

	if s.onShutdown != nil {
		s.onShutdown()
	}

	return nil
}

// RunHTTP starts the server in HTTP mode
func (s *Server) RunHTTP() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	mux := http.NewServeMux()

	// Main MCP endpoint
	mux.HandleFunc(s.config.Path, s.handleHTTP)

	// SSE endpoint
	if s.config.EnableSSE {
		mux.HandleFunc(s.config.Path+"/sse", s.handleSSE)
	}

	// REST API endpoints
	if s.config.EnableREST {
		s.setupRESTEndpoints(mux)
	}

	// Metrics endpoint
	if s.config.EnableMetrics {
		mux.HandleFunc("/metrics", s.handleMetrics)
	}

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Root handler
	mux.HandleFunc("/", s.handleRoot)

	var handler http.Handler = mux

	// Add CORS middleware
	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	s.config.Logger.Info("HTTP MCP Server started", "address", addr, "path", s.config.Path)

	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return s.httpServer.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return s.httpServer.ListenAndServe()
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
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

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}

// ----------------------------- Request Handling ----------------------------

func (s *Server) handleRequest(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.RequestCount++
	s.metrics.mu.Unlock()

	// Normalize method name (remove leading slash if present)
	method := strings.TrimPrefix(req.Method, "/")

	switch method {
	case "initialize":
		return s.handleInitialize(ctx, req)
	case "tools/list":
		return s.handleToolsList(ctx, req)
	case "tools/call":
		return s.handleToolCall(ctx, req)
	case "resources/list":
		return s.handleResourcesList(ctx, req)
	case "resources/read":
		return s.handleResourceRead(ctx, req)
	case "prompts/list":
		return s.handlePromptsList(ctx, req)
	case "prompts/get":
		return s.handlePromptGet(ctx, req)
	default:
		s.metrics.mu.Lock()
		s.metrics.ErrorCount++
		s.metrics.mu.Unlock()
		return nil, &RPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)}
	}
}

func (s *Server) handleInitialize(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	var params InitializeParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &RPCError{Code: -32602, Message: "Invalid params"}
		}
	}

	if s.onInit != nil {
		if err := s.onInit(&params); err != nil {
			return nil, &RPCError{Code: -32603, Message: err.Error()}
		}
	}

	s.config.Logger.Info("Client initialized", "name", params.ClientInfo.Name, "version", params.ClientInfo.Version)

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

func (s *Server) handleToolsList(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
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

func (s *Server) handleToolCall(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if req.Params == nil {
		return nil, &RPCError{Code: -32602, Message: "Missing params"}
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

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.ToolCalls[params.Name]++
	s.metrics.mu.Unlock()

	result, err := tool.handler(ctx, params.Arguments)
	if err != nil {
		if rpcErr, ok := err.(*RPCError); ok {
			return nil, rpcErr
		}
		return nil, &RPCError{Code: -32603, Message: err.Error()}
	}

	return result, nil
}

func (s *Server) handleResourcesList(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]map[string]interface{}, 0, len(s.resources))
	for _, resource := range s.resources {
		r := map[string]interface{}{
			"uri":         resource.URI,
			"name":        resource.Name,
			"description": resource.Description,
		}
		if resource.MimeType != "" {
			r["mimeType"] = resource.MimeType
		}
		resources = append(resources, r)
	}

	return map[string]interface{}{"resources": resources}, nil
}

func (s *Server) handleResourceRead(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
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

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.ResourceReads[params.URI]++
	s.metrics.mu.Unlock()

	content, err := resource.handler(ctx, params.URI)
	if err != nil {
		return nil, &RPCError{Code: -32603, Message: err.Error()}
	}

	return content, nil
}

func (s *Server) handlePromptsList(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	prompts := make([]map[string]interface{}, 0, len(s.prompts))
	for _, prompt := range s.prompts {
		p := map[string]interface{}{
			"name":        prompt.Name,
			"description": prompt.Description,
		}
		if len(prompt.Arguments) > 0 {
			p["arguments"] = prompt.Arguments
		}
		prompts = append(prompts, p)
	}

	return map[string]interface{}{"prompts": prompts}, nil
}

func (s *Server) handlePromptGet(ctx context.Context, req *JSONRPCRequest) (interface{}, *RPCError) {
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

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.PromptsUsed[params.Name]++
	s.metrics.mu.Unlock()

	result, err := prompt.handler(ctx, params.Arguments)
	if err != nil {
		return nil, &RPCError{Code: -32603, Message: err.Error()}
	}

	return result, nil
}

// ----------------------------- HTTP Handlers -------------------------------

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Check authentication
	if s.authProvider != nil {
		ok, err := s.authProvider.Authenticate(r)
		if err != nil {
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Handle GET (return server info)
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server": map[string]interface{}{
				"name":    s.config.Name,
				"version": s.config.Version,
			},
			"protocol": s.config.ProtocolVersion,
			"ready":    true,
		})
		return
	}

	// Handle POST (JSON-RPC)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Check for batch request
	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "[") {
		// Batch request
		var requests []JSONRPCRequest
		if err := json.Unmarshal(body, &requests); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(JSONRPCResponse{
				JSONRPC: "2.0",
				Error:   &RPCError{Code: -32700, Message: "Parse error"},
			})
			return
		}

		responses := make([]JSONRPCResponse, 0, len(requests))
		for _, req := range requests {
			if req.ID == nil {
				// Notification, no response
				s.handleRequest(r.Context(), &req)
				continue
			}

			result, rpcErr := s.handleRequest(r.Context(), &req)
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

		if len(responses) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responses)
		return
	}

	// Single request
	var request JSONRPCRequest
	if err := json.Unmarshal(body, &request); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &RPCError{Code: -32700, Message: "Parse error"},
		})
		return
	}

	// Handle notification
	if request.ID == nil {
		s.handleRequest(r.Context(), &request)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Handle normal request
	ctx := r.Context()
	if s.authProvider != nil {
		if principal, err := s.authProvider.GetPrincipal(r); err == nil {
			ctx = context.WithValue(ctx, "principal", principal)
		}
	}

	result, rpcErr := s.handleRequest(ctx, &request)

	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
	}

	if rpcErr != nil {
		response.Error = rpcErr
	} else {
		response.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Check if client accepts SSE
	if r.Header.Get("Accept") != "text/event-stream" {
		http.Error(w, "SSE not supported", http.StatusNotAcceptable)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create client
	clientID := fmt.Sprintf("%d", time.Now().UnixNano())
	client := &SSEClient{
		ID:       clientID,
		Events:   make(chan string, 10),
		Close:    make(chan bool),
		Response: w,
	}

	s.mu.Lock()
	s.sseClients[clientID] = client
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sseClients, clientID)
		s.mu.Unlock()
		close(client.Events)
		close(client.Close)
	}()

	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"id\":\"%s\"}\n\n", clientID)
	w.(http.Flusher).Flush()

	// Keep connection alive
	for {
		select {
		case event := <-client.Events:
			fmt.Fprintf(w, "%s\n\n", event)
			w.(http.Flusher).Flush()

		case <-client.Close:
			return

		case <-r.Context().Done():
			return

		case <-time.After(30 * time.Second):
			// Send ping to keep connection alive
			fmt.Fprintf(w, ":ping\n\n")
			w.(http.Flusher).Flush()
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	metrics := map[string]interface{}{
		"requests":  s.metrics.RequestCount,
		"errors":    s.metrics.ErrorCount,
		"tools":     s.metrics.ToolCalls,
		"resources": s.metrics.ResourceReads,
		"prompts":   s.metrics.PromptsUsed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>%s MCP Server</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
               max-width: 800px; margin: 0 auto; padding: 2rem; }
        h1 { color: #333; }
        .info { background: #f0f0f0; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        .endpoint { background: #fff; border: 1px solid #ddd; padding: 0.5rem 1rem; 
                   margin: 0.5rem 0; border-radius: 4px; }
        code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>%s v%s</h1>
    <div class="info">
        <p><strong>Protocol Version:</strong> %s</p>
        <p><strong>Status:</strong> Ready</p>
    </div>
    
    <h2>Endpoints</h2>
    <div class="endpoint">
        <strong>MCP Protocol:</strong> <code>POST %s</code>
    </div>`, s.config.Name, s.config.Name, s.config.Version, s.config.ProtocolVersion, s.config.Path)

	if s.config.EnableSSE {
		fmt.Fprintf(w, `
    <div class="endpoint">
        <strong>SSE Stream:</strong> <code>GET %s/sse</code>
    </div>`, s.config.Path)
	}

	if s.config.EnableREST {
		fmt.Fprintf(w, `
    <div class="endpoint">
        <strong>REST API:</strong> <code>/api/*</code>
    </div>`)
	}

	fmt.Fprintf(w, `
    <div class="endpoint">
        <strong>Health Check:</strong> <a href="/health"><code>GET /health</code></a>
    </div>`)

	if s.config.EnableMetrics {
		fmt.Fprintf(w, `
    <div class="endpoint">
        <strong>Metrics:</strong> <a href="/metrics"><code>GET /metrics</code></a>
    </div>`)
	}

	fmt.Fprintf(w, `
    
    <h2>Capabilities</h2>
    <div class="info">
        <p><strong>Tools:</strong> %d registered</p>
        <p><strong>Resources:</strong> %d registered</p>
        <p><strong>Prompts:</strong> %d registered</p>
    </div>
</body>
</html>`, len(s.tools), len(s.resources), len(s.prompts))
}

// ----------------------------- REST API ------------------------------------

func (s *Server) setupRESTEndpoints(mux *http.ServeMux) {
	// Tools REST API
	mux.HandleFunc("/api/tools", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		result, _ := s.handleToolsList(r.Context(), &JSONRPCRequest{})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/api/tools/", func(w http.ResponseWriter, r *http.Request) {
		toolName := strings.TrimPrefix(r.URL.Path, "/api/tools/")

		if r.Method == http.MethodGet {
			// Get tool info
			s.mu.RLock()
			tool, exists := s.tools[toolName]
			s.mu.RUnlock()

			if !exists {
				http.Error(w, "Tool not found", http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":        tool.Name,
				"description": tool.Description,
				"inputSchema": tool.InputSchema,
			})
			return
		}

		if r.Method == http.MethodPost {
			// Execute tool
			var args map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			req := &JSONRPCRequest{
				Method: "tools/call",
				Params: json.RawMessage(fmt.Sprintf(`{"name":"%s","arguments":%s}`,
					toolName, mustMarshal(args))),
			}

			result, rpcErr := s.handleToolCall(r.Context(), req)

			if rpcErr != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": rpcErr.Message,
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// Resources REST API
	mux.HandleFunc("/api/resources", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		result, _ := s.handleResourcesList(r.Context(), &JSONRPCRequest{})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// Prompts REST API
	mux.HandleFunc("/api/prompts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		result, _ := s.handlePromptsList(r.Context(), &JSONRPCRequest{})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// ----------------------------- CORS Middleware -----------------------------

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		if len(s.config.AllowedOrigins) > 0 {
			w.Header().Set("Access-Control-Allow-Origin", strings.Join(s.config.AllowedOrigins, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		if len(s.config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(s.config.AllowedMethods, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}

		if len(s.config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.AllowedHeaders, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if s.config.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ----------------------------- Helper Functions ----------------------------

func TextContent(text string) Content {
	return Content{Type: "text", Text: text}
}

func ImageContent(data string, mimeType string) Content {
	return Content{Type: "image", Data: data, MimeType: mimeType}
}

func ErrorResponse(code int, message string) error {
	return &RPCError{Code: code, Message: message}
}

func mustMarshal(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ----------------------------- Broadcast Methods ---------------------------

// BroadcastToSSE sends an event to all connected SSE clients
func (s *Server) BroadcastToSSE(event, data string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	message := fmt.Sprintf("event: %s\ndata: %s", event, data)

	for _, client := range s.sseClients {
		select {
		case client.Events <- message:
		default:
			// Client buffer full, skip
		}
	}
}

// NotifyToolsChanged notifies clients that tools have changed
func (s *Server) NotifyToolsChanged() {
	s.BroadcastToSSE("tools/list_changed", "{}")
}

// NotifyResourcesChanged notifies clients that resources have changed
func (s *Server) NotifyResourcesChanged() {
	s.BroadcastToSSE("resources/list_changed", "{}")
}

// NotifyPromptsChanged notifies clients that prompts have changed
func (s *Server) NotifyPromptsChanged() {
	s.BroadcastToSSE("prompts/list_changed", "{}")
}
