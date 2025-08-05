// Package mcp provides a framework for building Model Context Protocol servers
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
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

// Tool represents an executable tool in the MCP server
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema InputSchema `json:"inputSchema"`
	handler     ToolHandler
}

// InputSchema defines the JSON schema for tool inputs
type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
	Raw        json.RawMessage     `json:"-"` // For custom schemas
}

// Property defines a single property in an input schema
type Property struct {
	Type        string        `json:"type"`
	Description string        `json:"description,omitempty"`
	Default     interface{}   `json:"default,omitempty"`
	Enum        []interface{} `json:"enum,omitempty"`
}

// MarshalJSON handles both structured and raw schemas
func (i InputSchema) MarshalJSON() ([]byte, error) {
	if i.Raw != nil {
		return i.Raw, nil
	}
	type Alias InputSchema
	return json.Marshal(Alias(i))
}

// ToolHandler is the function signature for tool implementations
type ToolHandler func(ctx context.Context, args map[string]interface{}) (*ToolResult, error)

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Content []Content `json:"content"`
}

// Content represents a piece of content returned by a tool
type Content struct {
	Type     string      `json:"type"`
	Text     string      `json:"text,omitempty"`
	Data     interface{} `json:"data,omitempty"`
	MimeType string      `json:"mimeType,omitempty"`
}

// ============================================================================
// Resource System
// ============================================================================

// Resource represents a data resource in the MCP server
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
	handler     ResourceHandler
}

// ResourceHandler retrieves resource content
type ResourceHandler func(ctx context.Context, uri string) (*ResourceContent, error)

// ResourceContent represents the content of a resource
type ResourceContent struct {
	URI      string    `json:"uri"`
	MimeType string    `json:"mimeType,omitempty"`
	Content  []Content `json:"contents"`
}

// ============================================================================
// Prompt System
// ============================================================================

// Prompt represents a reusable prompt template
type Prompt struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Arguments   []PromptArg `json:"arguments,omitempty"`
	handler     PromptHandler
}

// PromptArg defines an argument for a prompt template
type PromptArg struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptHandler generates prompt content
type PromptHandler func(ctx context.Context, args map[string]string) (*PromptResult, error)

// PromptResult represents the result of prompt generation
type PromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptMessage represents a message in a prompt
type PromptMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// ============================================================================
// Server Implementation
// ============================================================================

// Server represents an MCP server instance
type Server struct {
	config    ServerConfig
	tools     map[string]*Tool
	resources map[string]*Resource
	prompts   map[string]*Prompt

	reader *bufio.Reader
	writer *bufio.Writer

	mu      sync.RWMutex
	running bool

	// Hooks for lifecycle events
	onInit     func(*InitializeParams) error
	onShutdown func() error

	// Middleware
	middleware []Middleware
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Name            string
	Version         string
	ProtocolVersion string

	// Custom IO (defaults to stdin/stdout)
	Input  io.Reader
	Output io.Writer

	// Logging
	Logger Logger
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

// NewServer creates a new MCP server instance
func NewServer(config ServerConfig) *Server {
	if config.ProtocolVersion == "" {
		config.ProtocolVersion = "0.1.0"
	}
	if config.Input == nil {
		config.Input = os.Stdin
	}
	if config.Output == nil {
		config.Output = os.Stdout
	}
	if config.Logger == nil {
		config.Logger = &defaultLogger{}
	}

	return &Server{
		config:    config,
		tools:     make(map[string]*Tool),
		resources: make(map[string]*Resource),
		prompts:   make(map[string]*Prompt),
		reader:    bufio.NewReader(config.Input),
		writer:    bufio.NewWriter(config.Output),
	}
}

// ============================================================================
// Registration Methods
// ============================================================================

// RegisterTool adds a tool to the server
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

	return nil
}

// RegisterSimpleTool provides a simplified way to register tools
func (s *Server) RegisterSimpleTool(name, description string, handler ToolHandler) error {
	schema := InputSchema{
		Type:       "object",
		Properties: map[string]Property{},
	}
	return s.RegisterTool(name, description, schema, handler)
}

// RegisterResource adds a resource to the server
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

	return nil
}

// RegisterPrompt adds a prompt template to the server
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

	return nil
}

// Use adds middleware to the server
func (s *Server) Use(m Middleware) {
	s.middleware = append(s.middleware, m)
}

// OnInitialize sets a callback for initialization
func (s *Server) OnInitialize(handler func(*InitializeParams) error) {
	s.onInit = handler
}

// OnShutdown sets a callback for shutdown
func (s *Server) OnShutdown(handler func() error) {
	s.onShutdown = handler
}

// ============================================================================
// Server Runtime
// ============================================================================

// Start begins listening for and processing requests
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	s.config.Logger.Info("MCP Server started", "name", s.config.Name, "version", s.config.Version)

	scanner := bufio.NewScanner(s.reader)
	for scanner.Scan() && s.running {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue // Skip empty lines
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.config.Logger.Error("Failed to parse request", "error", err, "line", string(line))
			s.sendError(nil, -32700, "Parse error", nil)
			continue
		}

		ctx := context.Background()
		s.handleRequest(ctx, &req)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		s.config.Logger.Error("Scanner error", "error", err)
	}

	if s.onShutdown != nil {
		return s.onShutdown()
	}

	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("server not running")
	}

	s.running = false
	return nil
}

// ============================================================================
// Request Handling
// ============================================================================

func (s *Server) handleRequest(ctx context.Context, req *JSONRPCRequest) {
	handler := s.getHandler(req.Method)

	// Apply middleware
	for i := len(s.middleware) - 1; i >= 0; i-- {
		handler = s.middleware[i](handler)
	}

	result, err := handler(ctx, req)
	if err != nil {
		if rpcErr, ok := err.(*RPCError); ok {
			s.sendError(req.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data)
		} else {
			s.sendError(req.ID, -32603, err.Error(), nil)
		}
		return
	}

	s.sendResult(req.ID, result)
}

func (s *Server) getHandler(method string) HandlerFunc {
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

func (s *Server) handleInitialize(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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

func (s *Server) handleToolsList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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

func (s *Server) handleToolCall(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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

func (s *Server) handleResourcesList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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

func (s *Server) handleResourceRead(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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

func (s *Server) handlePromptsList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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

func (s *Server) handlePromptGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
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
// Response Methods
// ============================================================================

func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.sendResponse(resp)
}

func (s *Server) sendError(id interface{}, code int, message string, data interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	s.sendResponse(resp)
}

func (s *Server) sendResponse(resp JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		s.config.Logger.Error("Failed to marshal response", "error", err)
		return
	}

	s.writer.Write(data)
	s.writer.WriteByte('\n')
	s.writer.Flush()
}

// ============================================================================
// Helper Types
// ============================================================================

type defaultLogger struct{}

func (l *defaultLogger) Debug(msg string, args ...interface{}) {}
func (l *defaultLogger) Info(msg string, args ...interface{})  {}
func (l *defaultLogger) Error(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: %s %v\n", msg, args)
}

// ============================================================================
// Convenience Functions
// ============================================================================

// TextContent creates a text content object
func TextContent(text string) Content {
	return Content{Type: "text", Text: text}
}

// ImageContent creates an image content object
func ImageContent(data string, mimeType string) Content {
	return Content{Type: "image", Data: data, MimeType: mimeType}
}

// ErrorResponse creates an RPC error
func ErrorResponse(code int, message string) error {
	return &RPCError{Code: code, Message: message}
}
