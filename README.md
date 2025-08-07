# myvue-mcp

A powerful Go library for building Model Context Protocol (MCP) servers with HTTP transport, authentication, and security features. Create type-safe MCP servers that seamlessly integrate with Claude Desktop, Claude.ai, and other MCP clients over HTTP/HTTPS.

## Features

- 🌐 **HTTP/HTTPS Transport** - Production-ready HTTP server with TLS support
- 🔐 **Built-in Authentication** - Token-based and API key authentication providers
- 🛡️ **Security First** - URL whitelisting, CORS configuration, and origin validation
- 🚀 **Simple, Idiomatic Go API** - Register tools, resources, and prompts with clean, type-safe handlers
- 🛠️ **Full MCP Protocol Support** - Implements the complete Model Context Protocol specification
- 🔌 **Extensible Architecture** - Middleware support, lifecycle hooks, and custom logging
- 📦 **Minimal Dependencies** - Built primarily with Go's standard library
- ⚡ **High Performance** - Concurrent request handling with configurable timeouts
- 🧪 **Production Ready** - Session management, health checks, and batch request support

## Installation

```bash
go get github.com/MyVueCodeHub/myvue-mcp
```

## Quick Start

Create a simple HTTP-based MCP server with authentication:

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    mcp "github.com/MyVueCodeHub/myvue-mcp"
)

func main() {
    // Create HTTP server configuration
    config := mcp.HTTPServerConfig{
        Name:    "my-mcp-server",
        Version: "1.0.0",
        Host:    "localhost",
        Port:    3000,
        Path:    "/mcp",
        
        // Enable CORS for Claude
        EnableCORS: true,
        AllowedOrigins: []string{
            "https://claude.ai",
            "https://*.claude.ai",
        },
    }
    
    // Create server
    server := mcp.NewHTTPServer(config)
    
    // Set up authentication
    tokenAuth := mcp.NewTokenAuthProvider()
    tokenAuth.AddToken("your-secret-token", "claude-client")
    server.SetAuthProvider(tokenAuth)
    
    // Set up URL whitelist
    whitelist := mcp.NewURLWhitelist()
    whitelist.AddOrigin("https://claude.ai")
    whitelist.AddPattern("https://*.claude.ai")
    server.SetURLWhitelist(whitelist)
    
    // Register a tool
    server.RegisterTool(
        "greet",
        "Generate a greeting message",
        mcp.InputSchema{
            Type: "object",
            Properties: map[string]mcp.Property{
                "name": {
                    Type:        "string",
                    Description: "Name to greet",
                },
            },
            Required: []string{"name"},
        },
        func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
            name := args["name"].(string)
            return &mcp.ToolResult{
                Content: []mcp.Content{
                    mcp.TextContent(fmt.Sprintf("Hello, %s! 👋", name)),
                },
            }, nil
        },
    )
    
    // Start server
    log.Printf("Starting MCP server on http://%s:%d%s", config.Host, config.Port, config.Path)
    if err := server.Start(); err != nil {
        log.Fatal(err)
    }
}
```

## Core Concepts

### HTTP Transport

Unlike traditional stdio-based MCP servers, this library uses HTTP transport for better scalability and deployment flexibility:

```go
config := mcp.HTTPServerConfig{
    Host: "0.0.0.0",           // Listen on all interfaces
    Port: 8080,                // Custom port
    Path: "/mcp",              // Base path for MCP endpoints
    
    // TLS Configuration
    TLSCert: "./certs/server.crt",
    TLSKey:  "./certs/server.key",
    
    // Timeouts
    ReadTimeout:  30 * time.Second,
    WriteTimeout: 30 * time.Second,
}
```

### Authentication

Protect your MCP server with built-in authentication providers:

#### Token Authentication (Bearer)
```go
tokenAuth := mcp.NewTokenAuthProvider()
tokenAuth.AddToken("secret-token-123", "client-1")
tokenAuth.AddToken("secret-token-456", "client-2")
server.SetAuthProvider(tokenAuth)
```

#### API Key Authentication
```go
apiKeyAuth := mcp.NewAPIKeyAuthProvider("X-API-Key")
apiKeyAuth.AddAPIKey("api-key-123", "service-1")
server.SetAuthProvider(apiKeyAuth)
```

#### Custom Authentication
```go
type CustomAuth struct{}

func (c *CustomAuth) Authenticate(r *http.Request) (bool, error) {
    // Your authentication logic
    return true, nil
}

func (c *CustomAuth) GetPrincipal(r *http.Request) (string, error) {
    return "user-id", nil
}

server.SetAuthProvider(&CustomAuth{})
```

### URL Whitelisting

Control which origins can access your server:

```go
whitelist := mcp.NewURLWhitelist()

// Exact matches
whitelist.AddOrigin("https://claude.ai")
whitelist.AddOrigin("https://app.example.com")

// Pattern matching with wildcards
whitelist.AddPattern("https://*.claude.ai")
whitelist.AddPattern("https://*.example.com")

server.SetURLWhitelist(whitelist)
```

### CORS Configuration

Fine-grained CORS control for browser-based clients:

```go
config := mcp.HTTPServerConfig{
    EnableCORS:       true,
    AllowedOrigins:   []string{"https://claude.ai", "https://*.claude.ai"},
    AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
    AllowedHeaders:   []string{"Content-Type", "Authorization"},
    AllowCredentials: true,
}
```

### Tools

Register tools that can be called by MCP clients:

```go
server.RegisterTool(
    "calculate",
    "Perform arithmetic