# go-mcp

A Go library for building Model Context Protocol (MCP) servers. Create powerful, type-safe MCP servers that seamlessly integrate with Claude Desktop and other MCP clients.

## Features

- 🚀 **Simple, idiomatic Go API** - Register tools, resources, and prompts with clean, type-safe handlers
- 🛠️ **Full MCP Protocol Support** - Implements the complete Model Context Protocol specification
- 🔌 **Extensible Architecture** - Middleware support, lifecycle hooks, and custom logging
- 📦 **Zero Dependencies** - Built using only Go's standard library
- 🧪 **Testing Ready** - Support for custom I/O streams and comprehensive error handling
- ⚡ **High Performance** - Leverages Go's concurrency model for efficient request handling

## Installation

```bash
go get github.com/MyVueCodeHub/go-mcp
```

## Quick Start

Create a simple MCP server with a single tool:

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/MyVueCodeHub/go-mcp"
)

func main() {
    // Create server
    server := mcp.NewServer(mcp.ServerConfig{
        Name:    "my-server",
        Version: "1.0.0",
    })
    
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
    if err := server.Start(); err != nil {
        log.Fatal(err)
    }
}
```

## Core Concepts

### Tools

Tools are functions that can be called by the MCP client to perform specific tasks.

```go
server.RegisterTool(
    "calculate",
    "Perform arithmetic operations",
    mcp.InputSchema{
        Type: "object",
        Properties: map[string]mcp.Property{
            "operation": {
                Type: "string",
                Enum: []interface{}{"add", "subtract", "multiply", "divide"},
            },
            "a": {Type: "number"},
            "b": {Type: "number"},
        },
        Required: []string{"operation", "a", "b"},
    },
    func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
        // Implementation here
        return &mcp.ToolResult{
            Content: []mcp.Content{
                mcp.TextContent("Result: 42"),
            },
        }, nil
    },
)
```

### Resources

Resources provide access to data that can be read by the MCP client.

```go
server.RegisterResource(
    "config://app",
    "Application Configuration",
    "Current app configuration settings",
    "application/json",
    func(ctx context.Context, uri string) (*mcp.ResourceContent, error) {
        config := map[string]interface{}{
            "theme": "dark",
            "language": "en",
        }
        return &mcp.ResourceContent{
            URI:      uri,
            MimeType: "application/json",
            Content: []mcp.Content{
                mcp.TextContent(jsonString(config)),
            },
        }, nil
    },
)
```

### Prompts

Prompts are reusable templates that help structure interactions.

```go
server.RegisterPrompt(
    "code_review",
    "Generate a code review prompt",
    []mcp.PromptArg{
        {Name: "language", Required: true},
        {Name: "code", Required: true},
    },
    func(ctx context.Context, args map[string]string) (*mcp.PromptResult, error) {
        return &mcp.PromptResult{
            Messages: []mcp.PromptMessage{
                {
                    Role: "user",
                    Content: mcp.TextContent(
                        fmt.Sprintf("Review this %s code:\n```%s\n%s\n```",
                            args["language"], args["language"], args["code"]),
                    ),
                },
            },
        }, nil
    },
)
```

## Advanced Features

### Middleware

Add cross-cutting concerns like logging, authentication, or rate limiting:

```go
server.Use(func(next mcp.HandlerFunc) mcp.HandlerFunc {
    return func(ctx context.Context, req *mcp.JSONRPCRequest) (interface{}, error) {
        start := time.Now()
        result, err := next(ctx, req)
        log.Printf("Method: %s, Duration: %v", req.Method, time.Since(start))
        return result, err
    }
})
```

### Lifecycle Hooks

Handle initialization and shutdown:

```go
server.OnInitialize(func(params *mcp.InitializeParams) error {
    log.Printf("Client connected: %s", params.ClientInfo.Name)
    return nil
})

server.OnShutdown(func() error {
    log.Println("Cleaning up resources...")
    return nil
})
```

### Custom Logging

Implement the Logger interface for custom logging:

```go
type MyLogger struct{}

func (l *MyLogger) Debug(msg string, args ...interface{}) {
    // Custom implementation
}

func (l *MyLogger) Info(msg string, args ...interface{}) {
    // Custom implementation
}

func (l *MyLogger) Error(msg string, args ...interface{}) {
    // Custom implementation
}

server := mcp.NewServer(mcp.ServerConfig{
    Name:   "my-server",
    Logger: &MyLogger{},
})
```

## Integration with Claude Desktop

1. Build your MCP server:
```bash
go build -o my-mcp-server main.go
```

2. Add to Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
```json
{
  "mcpServers": {
    "my-server": {
      "command": "/path/to/my-mcp-server"
    }
  }
}
```

3. Restart Claude Desktop to load your server.

## Testing

The library supports custom I/O streams for easy testing:

```go
func TestMyTool(t *testing.T) {
    input := bytes.NewBuffer([]byte{})
    output := bytes.NewBuffer([]byte{})
    
    server := mcp.NewServer(mcp.ServerConfig{
        Name:   "test-server",
        Input:  input,
        Output: output,
    })
    
    // Register tools and test
}
```

## API Reference

### Core Types

- `Server` - Main server instance
- `ServerConfig` - Server configuration
- `Tool` - Tool definition with handler
- `Resource` - Resource definition with handler
- `Prompt` - Prompt template with handler
- `InputSchema` - JSON Schema for tool inputs
- `Content` - Content objects (text, images, etc.)

### Registration Methods

- `RegisterTool(name, description, schema, handler)` - Register a tool
- `RegisterResource(uri, name, description, mimeType, handler)` - Register a resource
- `RegisterPrompt(name, description, args, handler)` - Register a prompt
- `Use(middleware)` - Add middleware
- `OnInitialize(handler)` - Set initialization hook
- `OnShutdown(handler)` - Set shutdown hook

### Helper Functions

- `TextContent(text)` - Create text content
- `ImageContent(data, mimeType)` - Create image content
- `ErrorResponse(code, message)` - Create error response

## Protocol Specification

This library implements the [Model Context Protocol](https://modelcontextprotocol.io) specification. Key protocol features:

- JSON-RPC 2.0 message format
- Stdio transport (stdin/stdout)
- Tool execution with typed inputs
- Resource reading with MIME types
- Prompt template expansion
- Client capability negotiation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [ ] WebSocket transport support
- [ ] Server-Sent Events (SSE) transport
- [ ] Tool composition and chaining
- [ ] Built-in rate limiting
- [ ] Metrics collection and reporting
- [ ] OpenTelemetry integration
- [ ] Automatic API documentation generation
- [ ] Plugin system for extended functionality
- [ ] CLI tool for server scaffolding

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic
- Inspired by the official TypeScript and Python SDKs
- Thanks to the Go community for the excellent standard library

## Support

- 📖 [Documentation](https://pkg.go.dev/github.com/MyVueCodeHub/go-mcp)
- 💬 [Discussions](https://github.com/MyVueCodeHub/go-mcp/discussions)
- 🐛 [Issue Tracker](https://github.com/MyVueCodeHub/go-mcp/issues)
- 📧 Email: info@myvue.io

---

Made with ❤️ by the myvue team