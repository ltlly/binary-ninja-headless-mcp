from __future__ import annotations

from typing import Any

from binary_ninja_headless_mcp.server import SimpleMcpServer


def _call_tool(
    server: SimpleMcpServer,
    name: str,
    arguments: dict[str, Any] | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert response is not None
    assert "error" not in response
    return response["result"]["structuredContent"]


def _open_analyzed(server: SimpleMcpServer, sample_binary_path: str) -> tuple[str, str]:
    opened = _call_tool(
        server,
        "session.open",
        {
            "path": sample_binary_path,
            "update_analysis": False,
            "read_only": False,
            "deterministic": True,
        },
        request_id=10,
    )
    session_id = opened["session_id"]
    _call_tool(
        server,
        "analysis.update_and_wait",
        {"session_id": session_id},
        request_id=11,
    )
    functions = _call_tool(
        server,
        "binary.functions",
        {"session_id": session_id, "offset": 0, "limit": 200},
        request_id=12,
    )["items"]
    for item in functions:
        if item["name"] == "main":
            return session_id, item["start"]
    raise AssertionError("main not found")


def test_core_tools_listed(real_server: SimpleMcpServer) -> None:
    listed = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 500},
        }
    )
    assert listed is not None
    names = {tool["name"] for tool in listed["result"]["tools"]}
    expected = {
        "value.flags_at",
        "function.var_refs_from",
        "function.ssa_var_def_use",
        "function.ssa_memory_def_use",
        "memory.reader_read",
        "memory.writer_write",
        "function.metadata_store",
        "function.metadata_query",
        "function.metadata_remove",
    }
    assert expected.issubset(names)


def test_core_tools_work(real_server: SimpleMcpServer, sample_binary_path: str) -> None:
    session_id, main_start = _open_analyzed(real_server, sample_binary_path)
    main_start_int = int(main_start, 16)

    il = _call_tool(
        real_server,
        "il.function",
        {
            "session_id": session_id,
            "function_start": main_start,
            "level": "mlil",
            "ssa": False,
            "offset": 0,
            "limit": 8,
        },
        request_id=20,
    )
    first = il["items"][0]
    assert isinstance(first["tokens"], list)
    assert "operands" in first
    assert "prefix_operands" in first

    _call_tool(
        real_server,
        "value.flags_at",
        {"session_id": session_id, "function_start": main_start, "address": main_start},
        request_id=21,
    )
    _call_tool(
        real_server,
        "function.var_refs_from",
        {
            "session_id": session_id,
            "function_start": main_start,
            "address": main_start,
            "level": "mlil",
        },
        request_id=22,
    )

    variables = _call_tool(
        real_server,
        "function.variables",
        {"session_id": session_id, "function_start": main_start},
        request_id=23,
    )
    var_name = variables["items"][0]["name"]
    _call_tool(
        real_server,
        "function.ssa_var_def_use",
        {
            "session_id": session_id,
            "function_start": main_start,
            "variable_name": var_name,
            "version": 0,
            "level": "mlil",
        },
        request_id=24,
    )
    _call_tool(
        real_server,
        "function.ssa_memory_def_use",
        {
            "session_id": session_id,
            "function_start": main_start,
            "version": 0,
            "level": "mlil",
        },
        request_id=25,
    )

    reader = _call_tool(
        real_server,
        "memory.reader_read",
        {
            "session_id": session_id,
            "address": main_start_int,
            "width": 1,
            "endian": "little",
        },
        request_id=26,
    )
    assert isinstance(reader["value"], int)
    writer = _call_tool(
        real_server,
        "memory.writer_write",
        {
            "session_id": session_id,
            "address": main_start_int,
            "width": 1,
            "value": reader["value"],
            "endian": "little",
        },
        request_id=27,
    )
    assert writer["written"] is True

    stored = _call_tool(
        real_server,
        "function.metadata_store",
        {
            "session_id": session_id,
            "function_start": main_start,
            "key": "mcp.fn.key",
            "value": {"hello": "world"},
        },
        request_id=28,
    )
    assert stored["value"]["hello"] == "world"
    queried = _call_tool(
        real_server,
        "function.metadata_query",
        {"session_id": session_id, "function_start": main_start, "key": "mcp.fn.key"},
        request_id=29,
    )
    assert queried["value"]["hello"] == "world"
    removed = _call_tool(
        real_server,
        "function.metadata_remove",
        {"session_id": session_id, "function_start": main_start, "key": "mcp.fn.key"},
        request_id=30,
    )
    assert removed["removed"] is True


def test_unexpected_tool_exception_is_reported_and_server_survives(
    real_server: SimpleMcpServer,
) -> None:
    def _boom(_: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("boom")

    real_server._tool_handlers["__boom__"] = _boom
    response = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 90,
            "method": "tools/call",
            "params": {"name": "__boom__", "arguments": {}},
        }
    )
    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert (
        response["result"]["structuredContent"]["error"]
        == "unexpected tool failure: RuntimeError: boom"
    )

    ping = _call_tool(real_server, "health.ping", request_id=91)
    assert ping["status"] == "ok"


def test_non_json_tool_payload_is_wrapped_and_server_survives(
    real_server: SimpleMcpServer,
) -> None:
    def _non_json(_: dict[str, Any]) -> dict[str, Any]:
        return {"value": object()}

    real_server._tool_handlers["__non_json__"] = _non_json
    response = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 92,
            "method": "tools/call",
            "params": {"name": "__non_json__", "arguments": {}},
        }
    )
    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    payload = response["result"]["structuredContent"]
    assert payload["error"] == "tool returned a non-JSON-serializable payload"
    assert "Object of type object is not JSON serializable" in payload["detail"]

    ping = _call_tool(real_server, "health.ping", request_id=93)
    assert ping["status"] == "ok"
