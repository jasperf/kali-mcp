"""
Tests for the server module functionality.
"""

from unittest.mock import patch

import mcp.types as types
import pytest

from kali_mcp_server.server import handle_tool_request


@pytest.mark.asyncio
async def test_handle_tool_request_unknown_tool():
    """Test handling of unknown tool calls."""
    with pytest.raises(ValueError, match="Unknown tool"):
        await handle_tool_request("unknown_tool", {})


@pytest.mark.asyncio
async def test_handle_tool_request_missing_arguments():
    """Test handling of tool calls with missing arguments."""
    with pytest.raises(ValueError, match="Missing required argument"):
        await handle_tool_request("fetch", {})  # Missing url

    with pytest.raises(ValueError, match="Missing required argument"):
        await handle_tool_request("run", {})  # Missing command


@pytest.mark.asyncio
async def test_handle_fetch_tool():
    """Test handling of fetch tool calls."""
    # Create a mock function directly
    async def mock_fetch(url):
        return [types.TextContent(type="text", text="Test content")]
    
    # Create a patch context
    with patch("kali_mcp_server.server.fetch_website", mock_fetch):
        # Call function
        result = await handle_tool_request("fetch", {"url": "https://example.com"})
        
        # Verify results
        assert len(result) == 1
        assert result[0].type == "text"
        assert result[0].text == "Test content"


@pytest.mark.asyncio
async def test_handle_run_tool():
    """Test handling of run tool calls."""
    # Create a mock function directly
    async def mock_run(command):
        return [types.TextContent(type="text", text="Command output")]
    
    # Create a patch context
    with patch("kali_mcp_server.server.run_command", mock_run):
        # Call function
        result = await handle_tool_request("run", {"command": "uname -a"})
        
        # Verify results
        assert len(result) == 1
        assert result[0].type == "text"
        assert result[0].text == "Command output"


@pytest.mark.asyncio
async def test_handle_resources_tool():
    """Test handling of resources tool calls."""
    # Create a mock function directly
    async def mock_resources():
        return [types.TextContent(type="text", text="Resources info")]
    
    # Create a patch context
    with patch("kali_mcp_server.server.list_system_resources", mock_resources):
        # Call function
        result = await handle_tool_request("resources", {})
        
        # Verify results
        assert len(result) == 1
        assert result[0].type == "text"
        assert result[0].text == "Resources info"