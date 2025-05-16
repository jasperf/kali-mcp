"""
MCP Server implementation for Kali Linux security tools.

This module provides the main server functionality for the Kali MCP Server,
including tool registration, transport configuration, and server initialization.
"""

from typing import Any, Dict, List, Sequence, Union

import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server

from .tools import fetch_website, list_system_resources, run_command

# Create server instance with descriptive name
kali_server = Server("kali-mcp-server")


@kali_server.call_tool()
async def handle_tool_request(
    name: str, arguments: Dict[str, Any]
) -> Sequence[Union[types.TextContent, types.ImageContent, types.EmbeddedResource]]:
    """
    Handle MCP tool requests by routing to the appropriate handler.
    
    Args:
        name: The name of the tool being called
        arguments: Dictionary of arguments for the tool
        
    Returns:
        Sequence of content items returned by the tool
        
    Raises:
        ValueError: If the tool name is unknown or required arguments are missing
    """
    if name == "fetch":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        return await fetch_website(arguments["url"])
    
    elif name == "run":
        if "command" not in arguments:
            raise ValueError("Missing required argument 'command'")
        return await run_command(arguments["command"])
    
    elif name == "resources":
        return await list_system_resources()
    
    else:
        raise ValueError(f"Unknown tool: {name}")


@kali_server.list_tools()
async def list_available_tools() -> List[types.Tool]:
    """
    Register and list all available MCP tools.
    
    Returns:
        List of available Tool objects
    """
    return [
        types.Tool(
            name="fetch",
            description="Fetches a website and returns its content",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    }
                },
            },
        ),
        types.Tool(
            name="run",
            description="Runs a shell command on the Kali Linux system",
            inputSchema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    }
                },
            },
        ),
        types.Tool(
            name="resources",
            description="Lists available system resources and command examples",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        )
    ]


@click.command()
@click.option("--port", default=8000, help="Port to listen on for HTTP/SSE connections")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="sse",
    help="Transport type (stdio for command line, sse for Claude Desktop)"
)
@click.option(
    "--debug", 
    is_flag=True, 
    default=False, 
    help="Enable debug mode"
)
def main(port: int, transport: str, debug: bool) -> int:
    """
    Start the Kali MCP Server with the specified transport.
    
    Args:
        port: Port number to listen on when using SSE transport
        transport: Transport type (stdio or SSE)
        debug: Enable debug mode
        
    Returns:
        Exit code (0 for success)
    """
    if transport == "sse":
        return start_sse_server(port, debug)
    else:
        return start_stdio_server(debug)


def start_sse_server(port: int, debug: bool) -> int:
    """
    Start the server with SSE transport for web/Claude Desktop usage.
    
    Args:
        port: Port number to listen on
        debug: Enable debug mode
        
    Returns:
        Exit code (0 for success)
    """
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    # Create SSE transport handler
    sse_transport = SseServerTransport("/messages/")

    async def handle_sse_connection(request):
        """Handle incoming SSE connections."""
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await kali_server.run(
                streams[0], streams[1], kali_server.create_initialization_options()
            )

    # Configure Starlette routes
    starlette_app = Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse_connection),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

    # Run the server
    print(f"Starting Kali MCP Server with SSE transport on port {port}")
    print(f"Connect to this server using: http://localhost:{port}/sse")
    uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    return 0


def start_stdio_server(debug: bool) -> int:
    """
    Start the server with stdio transport for command-line usage.
    
    Args:
        debug: Enable debug mode
        
    Returns:
        Exit code (0 for success)
    """
    from mcp.server.stdio import stdio_server

    async def start_stdio_connection():
        """Initialize and run the stdio server."""
        print("Starting Kali MCP Server with stdio transport")
        async with stdio_server() as streams:
            await kali_server.run(
                streams[0], streams[1], kali_server.create_initialization_options()
            )

    # Run the server
    anyio.run(start_stdio_connection)
    return 0


if __name__ == "__main__":
    main()