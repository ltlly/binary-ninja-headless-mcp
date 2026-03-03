from __future__ import annotations

import uuid
from pathlib import Path
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


def _open_rw(server: SimpleMcpServer, sample_binary_path: str, request_id: int) -> str:
    opened = _call_tool(
        server,
        "session.open",
        {
            "path": sample_binary_path,
            "update_analysis": False,
            "read_only": False,
            "deterministic": True,
        },
        request_id=request_id,
    )
    session_id = opened["session_id"]
    assert isinstance(session_id, str)
    return session_id


def _find_function_start(items: list[dict[str, Any]], name: str) -> str:
    for item in items:
        if item.get("name") == name:
            start = item.get("start")
            if isinstance(start, str):
                return start
    raise AssertionError(f"function not found: {name}")


def test_tools_list_includes_advanced_tools(real_server: SimpleMcpServer) -> None:
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
        "type.parse_string",
        "type.parse_declarations",
        "type.define_user",
        "type.rename",
        "type.undefine_user",
        "type.import_library_type",
        "type.import_library_object",
        "type.export_to_library",
        "type_library.create",
        "type_library.load",
        "type_library.list",
        "type_library.get",
        "type_archive.create",
        "type_archive.open",
        "type_archive.list",
        "type_archive.get",
        "type_archive.pull",
        "type_archive.push",
        "type_archive.references",
        "debug.parsers",
        "debug.parse_and_apply",
        "workflow.list",
        "workflow.describe",
        "workflow.clone",
        "workflow.insert",
        "workflow.insert_after",
        "workflow.remove",
        "workflow.graph",
        "workflow.machine.status",
        "workflow.machine.control",
        "il.rewrite.capabilities",
        "il.rewrite.noop_replace",
        "il.rewrite.translate_identity",
        "uidf.parse_possible_value",
        "uidf.set_user_var_value",
        "uidf.clear_user_var_value",
        "uidf.list_user_var_values",
        "loader.rebase",
        "loader.load_settings_types",
        "loader.load_settings_get",
        "loader.load_settings_set",
        "segment.add_user",
        "segment.remove_user",
        "section.add_user",
        "section.remove_user",
        "external.library_add",
        "external.library_list",
        "external.library_remove",
        "external.location_add",
        "external.location_get",
        "external.location_remove",
        "arch.info",
        "arch.disasm_bytes",
        "arch.assemble",
        "transform.inspect",
        "project.create",
        "project.open",
        "project.close",
        "project.list",
        "project.create_folder",
        "project.create_file",
        "project.metadata_store",
        "project.metadata_query",
        "project.metadata_remove",
        "database.info",
        "database.snapshots",
        "database.read_global",
        "database.write_global",
        "plugin.valid_commands",
        "plugin.execute",
        "plugin_repo.status",
        "plugin_repo.check_updates",
        "plugin_repo.plugin_action",
        "baseaddr.detect",
        "baseaddr.reasons",
        "baseaddr.abort",
    }
    assert expected.issubset(names)


def test_server_advanced_tool_calls_end_to_end(  # noqa: PLR0915
    real_server: SimpleMcpServer,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open_rw(real_server, sample_binary_path, request_id=10)
    _call_tool(
        real_server,
        "analysis.update_and_wait",
        {"session_id": session_id},
        request_id=11,
    )

    parsed = _call_tool(
        real_server,
        "type.parse_string",
        {"session_id": session_id, "type_source": "int mcp_type(int x);"},
        request_id=12,
    )
    assert parsed["parsed_name"] == "mcp_type"

    parsed_decls = _call_tool(
        real_server,
        "type.parse_declarations",
        {
            "session_id": session_id,
            "declarations": "typedef struct { int x; } mcp_s; int mcp_fn(int a);",
        },
        request_id=13,
    )
    assert parsed_decls["type_count"] >= 1

    _call_tool(
        real_server,
        "type.define_user",
        {
            "session_id": session_id,
            "type_source": "int mcp_defined_t;",
            "name": "mcp_defined_t",
        },
        request_id=14,
    )
    _call_tool(
        real_server,
        "type.rename",
        {
            "session_id": session_id,
            "old_name": "mcp_defined_t",
            "new_name": "mcp_defined_t2",
        },
        request_id=15,
    )
    _call_tool(
        real_server,
        "type.undefine_user",
        {"session_id": session_id, "name": "mcp_defined_t2"},
        request_id=16,
    )

    library_path = tmp_path / "server_types.bntl"
    created_library = _call_tool(
        real_server,
        "type_library.create",
        {
            "session_id": session_id,
            "name": "mcp_lib",
            "path": str(library_path),
        },
        request_id=17,
    )
    type_library_id = created_library["type_library"]["type_library_id"]
    assert library_path.exists()

    exported = _call_tool(
        real_server,
        "type.export_to_library",
        {
            "session_id": session_id,
            "type_library_id": type_library_id,
            "type_source": "int mcp_lib_type;",
            "name": "mcp_lib_type",
        },
        request_id=18,
    )
    assert exported["exported"] is True

    imported = _call_tool(
        real_server,
        "type.import_library_type",
        {
            "session_id": session_id,
            "name": "mcp_lib_type",
            "type_library_id": type_library_id,
        },
        request_id=19,
    )
    assert imported["imported"] is True

    _call_tool(
        real_server,
        "type.import_library_object",
        {
            "session_id": session_id,
            "name": "mcp_lib_type",
            "type_library_id": type_library_id,
        },
        request_id=20,
    )

    assert (
        _call_tool(
            real_server,
            "type_library.list",
            {"session_id": session_id},
            request_id=21,
        )["count"]
        >= 1
    )
    _call_tool(
        real_server,
        "type_library.get",
        {"session_id": session_id, "type_library_id": type_library_id},
        request_id=22,
    )
    loaded_library = _call_tool(
        real_server,
        "type_library.load",
        {
            "session_id": session_id,
            "path": str(library_path),
            "add_to_view": True,
        },
        request_id=23,
    )
    assert loaded_library["type_library"]["name"] == "mcp_lib"

    archive_path = tmp_path / "server_types.bnta"
    created_archive = _call_tool(
        real_server,
        "type_archive.create",
        {"session_id": session_id, "path": str(archive_path), "attach": True},
        request_id=24,
    )
    type_archive_id = created_archive["type_archive"]["type_archive_id"]
    assert archive_path.exists()

    _call_tool(
        real_server,
        "type_archive.open",
        {"session_id": session_id, "path": str(archive_path), "attach": True},
        request_id=25,
    )
    assert (
        _call_tool(
            real_server,
            "type_archive.list",
            {"session_id": session_id},
            request_id=26,
        )["count"]
        >= 1
    )
    _call_tool(
        real_server,
        "type_archive.get",
        {"session_id": session_id, "type_archive_id": type_archive_id},
        request_id=27,
    )
    _call_tool(
        real_server,
        "type_archive.pull",
        {
            "session_id": session_id,
            "type_archive_id": type_archive_id,
            "names": ["mcp_lib_type"],
        },
        request_id=28,
    )
    _call_tool(
        real_server,
        "type_archive.push",
        {
            "session_id": session_id,
            "type_archive_id": type_archive_id,
            "names": ["mcp_lib_type"],
        },
        request_id=29,
    )
    _call_tool(
        real_server,
        "type_archive.references",
        {"type_archive_id": type_archive_id, "name": "mcp_lib_type"},
        request_id=30,
    )

    parsers = _call_tool(
        real_server,
        "debug.parsers",
        {"session_id": session_id},
        request_id=31,
    )
    assert parsers["count"] >= 1
    parsed_debug = _call_tool(
        real_server,
        "debug.parse_and_apply",
        {"session_id": session_id},
        request_id=32,
    )
    assert parsed_debug["applied"] is True

    workflows = _call_tool(real_server, "workflow.list", request_id=33)
    assert workflows["count"] >= 1
    workflow_desc = _call_tool(
        real_server,
        "workflow.describe",
        {"session_id": session_id},
        request_id=34,
    )
    assert isinstance(workflow_desc["name"], str)
    _call_tool(
        real_server,
        "workflow.graph",
        {"session_id": session_id},
        request_id=35,
    )
    _call_tool(
        real_server,
        "workflow.machine.status",
        {"session_id": session_id},
        request_id=36,
    )
    _call_tool(
        real_server,
        "workflow.machine.control",
        {"session_id": session_id, "action": "dump"},
        request_id=37,
    )
    clone_name = f"mcp_clone_{uuid.uuid4().hex[:8]}"
    _call_tool(
        real_server,
        "workflow.clone",
        {"session_id": session_id, "name": clone_name},
        request_id=38,
    )
    activity = ""
    if workflow_desc["subactivities"]:
        activity = workflow_desc["subactivities"][0]
    elif workflow_desc["roots"]:
        activity = workflow_desc["roots"][0]
    if activity:
        _call_tool(
            real_server,
            "workflow.insert",
            {
                "session_id": session_id,
                "workflow_name": clone_name,
                "activity": activity,
                "activities": [activity],
            },
            request_id=39,
        )
        _call_tool(
            real_server,
            "workflow.insert_after",
            {
                "session_id": session_id,
                "workflow_name": clone_name,
                "activity": activity,
                "activities": [activity],
            },
            request_id=40,
        )
        _call_tool(
            real_server,
            "workflow.remove",
            {"session_id": session_id, "workflow_name": clone_name, "activity": activity},
            request_id=41,
        )

    functions = _call_tool(
        real_server,
        "binary.functions",
        {"session_id": session_id, "offset": 0, "limit": 200},
        request_id=42,
    )
    main_start = _find_function_start(functions["items"], "main")
    _call_tool(
        real_server,
        "il.rewrite.capabilities",
        {"session_id": session_id, "function_start": main_start, "level": "mlil"},
        request_id=43,
    )
    _call_tool(
        real_server,
        "il.rewrite.noop_replace",
        {"session_id": session_id, "function_start": main_start, "level": "mlil"},
        request_id=44,
    )
    _call_tool(
        real_server,
        "il.rewrite.translate_identity",
        {"session_id": session_id, "function_start": main_start, "level": "mlil"},
        request_id=45,
    )

    variables = _call_tool(
        real_server,
        "function.variables",
        {"session_id": session_id, "function_start": main_start},
        request_id=46,
    )
    first_var_name = variables["items"][0]["name"]
    _call_tool(
        real_server,
        "uidf.parse_possible_value",
        {"session_id": session_id, "value": "0x2a", "state": "ConstantValue"},
        request_id=47,
    )
    _call_tool(
        real_server,
        "uidf.set_user_var_value",
        {
            "session_id": session_id,
            "function_start": main_start,
            "variable_name": first_var_name,
            "def_addr": main_start,
            "value": "0x2a",
            "state": "ConstantValue",
        },
        request_id=48,
    )
    _call_tool(
        real_server,
        "uidf.list_user_var_values",
        {"session_id": session_id, "function_start": main_start},
        request_id=49,
    )
    _call_tool(
        real_server,
        "uidf.clear_user_var_value",
        {
            "session_id": session_id,
            "function_start": main_start,
            "variable_name": first_var_name,
            "def_addr": main_start,
        },
        request_id=50,
    )

    summary = _call_tool(
        real_server,
        "binary.summary",
        {"session_id": session_id},
        request_id=51,
    )
    base = int(summary["end"], 16) + 0x2000
    _call_tool(
        real_server,
        "segment.add_user",
        {"session_id": session_id, "start": base, "length": 0x1000},
        request_id=52,
    )
    _call_tool(
        real_server,
        "segment.remove_user",
        {"session_id": session_id, "start": base},
        request_id=53,
    )
    _call_tool(
        real_server,
        "section.add_user",
        {"session_id": session_id, "name": ".mcpsec", "start": base, "length": 0x100},
        request_id=54,
    )
    _call_tool(
        real_server,
        "section.remove_user",
        {"session_id": session_id, "name": ".mcpsec"},
        request_id=55,
    )

    load_types = _call_tool(
        real_server,
        "loader.load_settings_types",
        {"session_id": session_id},
        request_id=56,
    )
    assert load_types["count"] >= 1
    load_type_name = load_types["items"][0]
    _call_tool(
        real_server,
        "loader.load_settings_get",
        {"session_id": session_id, "type_name": load_type_name},
        request_id=57,
    )
    _call_tool(
        real_server,
        "loader.load_settings_set",
        {
            "session_id": session_id,
            "type_name": load_type_name,
            "key": "loader.imageBase",
            "value": "0x400000",
            "value_type": "string",
        },
        request_id=58,
    )

    _call_tool(
        real_server,
        "external.library_add",
        {"session_id": session_id, "name": "mcp_ext_lib"},
        request_id=59,
    )
    _call_tool(
        real_server,
        "external.library_list",
        {"session_id": session_id},
        request_id=60,
    )
    _call_tool(
        real_server,
        "external.location_add",
        {
            "session_id": session_id,
            "source_address": main_start,
            "library_name": "mcp_ext_lib",
            "target_symbol": "mcp_target",
        },
        request_id=61,
    )
    _call_tool(
        real_server,
        "external.location_get",
        {"session_id": session_id, "source_address": main_start},
        request_id=62,
    )
    _call_tool(
        real_server,
        "external.location_remove",
        {"session_id": session_id, "source_address": main_start},
        request_id=63,
    )
    _call_tool(
        real_server,
        "external.library_remove",
        {"session_id": session_id, "name": "mcp_ext_lib"},
        request_id=64,
    )

    _call_tool(real_server, "arch.info", {"session_id": session_id}, request_id=65)
    _call_tool(
        real_server,
        "arch.disasm_bytes",
        {"session_id": session_id, "data_hex": "9090", "address": 0x1000},
        request_id=66,
    )
    _call_tool(
        real_server,
        "arch.assemble",
        {"session_id": session_id, "asm": "nop", "address": 0x1000},
        request_id=67,
    )
    _call_tool(
        real_server,
        "transform.inspect",
        {"path": sample_binary_path, "mode": "full", "process": False},
        request_id=68,
    )

    project_path = tmp_path / "server_project"
    project = _call_tool(
        real_server,
        "project.create",
        {"path": str(project_path), "name": "mcp-proj"},
        request_id=69,
    )
    project_id = project["project"]["project_id"]
    _call_tool(real_server, "project.list", {"project_id": project_id}, request_id=70)
    folder = _call_tool(
        real_server,
        "project.create_folder",
        {"project_id": project_id, "name": "docs"},
        request_id=71,
    )["folder"]
    _call_tool(
        real_server,
        "project.create_file",
        {
            "project_id": project_id,
            "name": "note.txt",
            "data_base64": "SGVsbG8=",
            "folder_id": folder["id"],
        },
        request_id=72,
    )
    _call_tool(
        real_server,
        "project.metadata_store",
        {"project_id": project_id, "key": "mcp.key", "value": {"v": 1}},
        request_id=73,
    )
    _call_tool(
        real_server,
        "project.metadata_query",
        {"project_id": project_id, "key": "mcp.key"},
        request_id=74,
    )
    _call_tool(
        real_server,
        "project.metadata_remove",
        {"project_id": project_id, "key": "mcp.key"},
        request_id=75,
    )
    _call_tool(real_server, "project.close", {"project_id": project_id}, request_id=76)

    bndb_path = tmp_path / "server_hello.bndb"
    _call_tool(
        real_server,
        "database.create_bndb",
        {"session_id": session_id, "path": str(bndb_path)},
        request_id=77,
    )
    bndb_session = _call_tool(
        real_server,
        "session.open",
        {
            "path": str(bndb_path),
            "update_analysis": False,
            "read_only": False,
            "deterministic": True,
        },
        request_id=78,
    )["session_id"]
    _call_tool(
        real_server,
        "database.info",
        {"session_id": bndb_session},
        request_id=79,
    )
    _call_tool(
        real_server,
        "database.snapshots",
        {"session_id": bndb_session, "offset": 0, "limit": 20},
        request_id=80,
    )
    _call_tool(
        real_server,
        "database.write_global",
        {"session_id": bndb_session, "key": "mcp.key", "value": "value"},
        request_id=81,
    )
    _call_tool(
        real_server,
        "database.read_global",
        {"session_id": bndb_session, "key": "mcp.key"},
        request_id=82,
    )

    plugins = _call_tool(
        real_server,
        "plugin.valid_commands",
        {"session_id": session_id},
        request_id=85,
    )
    if plugins["items"]:
        _call_tool(
            real_server,
            "plugin.execute",
            {"session_id": session_id, "name": plugins["items"][0]["name"]},
            request_id=86,
        )

    _call_tool(real_server, "plugin_repo.status", request_id=87)
    _call_tool(real_server, "plugin_repo.check_updates", request_id=88)

    base_detect = _call_tool(
        real_server,
        "baseaddr.detect",
        {"session_id": session_id, "analysis": "basic"},
        request_id=89,
    )
    if base_detect["scores"]:
        _call_tool(
            real_server,
            "baseaddr.reasons",
            {"session_id": session_id, "base_address": base_detect["scores"][0]["base_address"]},
            request_id=90,
        )
    _call_tool(
        real_server,
        "baseaddr.abort",
        {"session_id": session_id},
        request_id=91,
    )

    _call_tool(
        real_server,
        "loader.rebase",
        {"session_id": session_id, "address": summary["start"]},
        request_id=90,
    )
