from __future__ import annotations

import ctypes
from dataclasses import dataclass

from binary_ninja_headless_mcp.backend import BinjaBackend


def _open_analyzed(real_backend: BinjaBackend, sample_binary_path: str) -> tuple[str, str]:
    opened = real_backend.open_session(
        sample_binary_path,
        update_analysis=False,
        read_only=False,
        deterministic=True,
    )
    session_id = opened["session_id"]
    real_backend.analysis_update(session_id, wait=True)
    functions = real_backend.list_functions(session_id, offset=0, limit=200)
    for item in functions["items"]:
        if item["name"] == "main":
            return session_id, item["start"]
    raise AssertionError("main not found")


def test_core_il_and_dataflow_additional_features(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, main_start = _open_analyzed(real_backend, sample_binary_path)

    il = real_backend.il_function(
        session_id,
        main_start,
        level="mlil",
        ssa=False,
        offset=0,
        limit=8,
    )
    assert il["count"] if "count" in il else il["total"] >= 1
    first = il["items"][0]
    assert "tokens" in first
    assert isinstance(first["tokens"], list)
    assert "operands" in first
    assert "prefix_operands" in first
    assert "possible_values" in first

    il_by_addr = real_backend.il_instruction_by_addr(
        session_id,
        main_start,
        first["address"],
        level="mlil",
        ssa=False,
    )
    assert isinstance(il_by_addr["instruction"]["tokens"], list)

    flags = real_backend.function_flags_at(session_id, main_start, main_start)
    assert "flags_read" in flags
    assert "flags_written" in flags
    assert "read_definitions" in flags
    assert "write_uses" in flags

    refs_from = real_backend.function_variable_refs_from(
        session_id,
        main_start,
        main_start,
        level="mlil",
    )
    assert refs_from["count"] >= 0

    variables = real_backend.function_variables(session_id, main_start)
    assert variables["count"] >= 1
    variable_name = variables["items"][0]["name"]

    ssa_var = real_backend.function_ssa_var_def_use(
        session_id,
        main_start,
        variable_name,
        0,
        level="mlil",
    )
    assert "uses" in ssa_var
    assert ssa_var["use_count"] >= 0

    ssa_mem = real_backend.function_ssa_memory_def_use(
        session_id,
        main_start,
        0,
        level="mlil",
    )
    assert "uses" in ssa_mem
    assert ssa_mem["use_count"] >= 0


def test_core_reader_writer_and_function_metadata_additional_features(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, main_start = _open_analyzed(real_backend, sample_binary_path)
    main_start_int = int(main_start, 16)

    reader = real_backend.reader_read(session_id, main_start_int, 1, endian="little")
    assert isinstance(reader["value"], int)

    writer = real_backend.writer_write(
        session_id,
        main_start_int,
        1,
        reader["value"],
        endian="little",
    )
    assert writer["written"] is True

    stored = real_backend.function_metadata_store(
        session_id,
        main_start,
        "mcp.fn.key",
        {"hello": "world"},
    )
    assert stored["value"]["hello"] == "world"

    queried = real_backend.function_metadata_query(session_id, main_start, "mcp.fn.key")
    assert queried["value"]["hello"] == "world"

    removed = real_backend.function_metadata_remove(session_id, main_start, "mcp.fn.key")
    assert removed["removed"] is True


@dataclass
class _PointerPayload:
    value: object


def test_to_jsonable_handles_dataclass_with_ctypes_pointer(real_backend: BinjaBackend) -> None:
    int_value = ctypes.c_int(7)
    pointer_value = ctypes.pointer(int_value)
    payload = _PointerPayload(value=pointer_value)

    converted = real_backend._to_jsonable(payload)
    assert isinstance(converted, dict)
    assert "value" in converted
    assert isinstance(converted["value"], str)
