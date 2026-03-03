from __future__ import annotations

import base64
from concurrent.futures import Future
from typing import ClassVar

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend, BinjaBackendError, TaskRecord


def _open_rw(real_backend: BinjaBackend, sample_binary_path: str) -> str:
    summary = real_backend.open_session(
        sample_binary_path,
        update_analysis=False,
        read_only=False,
        deterministic=True,
    )
    return summary["session_id"]


def _open_analyzed(real_backend: BinjaBackend, sample_binary_path: str) -> tuple[str, str, int]:
    session_id = _open_rw(real_backend, sample_binary_path)
    real_backend.analysis_update(session_id, wait=True)
    functions = real_backend.list_functions(session_id, offset=0, limit=200)
    main_start = _find_function_start(functions, "main")
    return session_id, main_start, int(main_start, 16)


def _find_function_start(functions: dict[str, object], name: str) -> str:
    for item in functions["items"]:  # type: ignore[index]
        if isinstance(item, dict) and item.get("name") == name:
            start = item.get("start")
            if isinstance(start, str):
                return start
    raise AssertionError(f"function not found: {name}")


def _assert_hex_match(match: object) -> None:
    assert isinstance(match, str)
    assert "databuffer" not in match.lower()
    int(match, 16)


def _find_patch_address(real_backend: BinjaBackend, session_id: str, start: int, end: int) -> int:
    for address in range(start, end, 4):
        status = real_backend.patch_status(session_id, address)
        if (
            status["is_always_branch_patch_available"]
            or status["is_never_branch_patch_available"]
            or status["is_invert_branch_patch_available"]
            or status["is_skip_and_return_value_patch_available"]
        ):
            return address
    raise AssertionError("no patchable address found")


def test_session_open_bytes_and_existing(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    original = real_backend.open_session(sample_binary_path, update_analysis=False)
    source_session_id = original["session_id"]

    with open(sample_binary_path, "rb") as handle:
        raw = handle.read()

    data_base64 = base64.b64encode(raw).decode("ascii")
    from_bytes = real_backend.open_session_from_bytes(
        data_base64,
        filename="hello-from-bytes",
        update_analysis=False,
    )
    assert from_bytes["function_count"] >= 1

    from_existing = real_backend.open_session_from_existing(
        source_session_id,
        update_analysis=False,
        read_only=True,
    )
    assert from_existing["filename"] == sample_binary_path


def test_search_navigation_and_linear_disasm(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, main_start, _ = _open_analyzed(real_backend, sample_binary_path)
    summary = real_backend.binary_summary(session_id)
    start = int(summary["start"], 16)
    end = int(summary["end"], 16)

    assert real_backend.list_functions_at(session_id, main_start)["count"] >= 1
    assert real_backend.list_basic_blocks_at(session_id, main_start)["count"] >= 1
    assert real_backend.list_function_basic_blocks(session_id, main_start)["count"] >= 1
    assert real_backend.disasm_linear(session_id, offset=0, limit=20)["total"] >= 1

    search_data = real_backend.search_data(
        session_id,
        "48656c6c6f",
        start=start,
        end=end,
        limit=10,
    )
    assert search_data["count"] >= 1
    _assert_hex_match(search_data["items"][0]["match"])
    assert real_backend.find_next_text(session_id, start, "Hello")["found"] is True

    all_text = real_backend.find_all_text(session_id, start, end, "Hello", regex=False, limit=10)
    assert all_text["count"] >= 1
    regex_text = real_backend.find_all_text(session_id, start, end, "Hel+o", regex=True, limit=10)
    assert regex_text["count"] >= 1
    assert real_backend.find_next_data(session_id, start, "48656c6c6f")["found"] is True
    assert real_backend.find_all_data(session_id, start, end, "48656c6c6f", limit=10)["count"] >= 1
    assert "found" in real_backend.find_next_constant(session_id, start, 1)
    assert real_backend.find_all_constant(session_id, start, end, 1, limit=10)["count"] >= 0


def test_dataflow_memory_and_typed_data(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, main_start, main_start_int = _open_analyzed(real_backend, sample_binary_path)

    reg_value = real_backend.function_reg_value(session_id, main_start, main_start, "x0")
    assert "value" in reg_value

    stack_value = real_backend.function_stack_contents(session_id, main_start, main_start, 0, 8)
    assert "value" in stack_value

    variables = real_backend.function_variables(session_id, main_start)
    assert variables["count"] >= 1

    first_var_name = variables["items"][0]["name"]
    refs = real_backend.function_variable_refs(session_id, main_start, first_var_name, level="mlil")
    assert refs["count"] >= 0

    possible = real_backend.il_possible_values(session_id, main_start, main_start, level="mlil")
    assert "possible_values" in possible

    read = real_backend.read_bytes(session_id, main_start, 4)
    assert len(read["data_hex"]) == 8

    assert real_backend.write_bytes(session_id, main_start, read["data_hex"])["written"] >= 0
    assert real_backend.insert_bytes(session_id, main_start_int + 4, "00")["inserted"] >= 0
    assert real_backend.remove_bytes(session_id, main_start_int + 4, 1)["removed"] >= 0

    search = real_backend.search_text(session_id, "Hello", limit=5)
    _assert_hex_match(search["items"][0]["match"])
    typed = real_backend.typed_data_at(session_id, search["items"][0]["address"])
    assert typed["data_var"]["address"].startswith("0x")


def test_rebase_blocked_after_byte_edits(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, main_start, _ = _open_analyzed(real_backend, sample_binary_path)
    summary = real_backend.binary_summary(session_id)

    original = real_backend.read_bytes(session_id, main_start, 4)
    real_backend.write_bytes(session_id, main_start, original["data_hex"])

    with pytest.raises(BinjaBackendError, match="rebase is not allowed after byte edits"):
        real_backend.loader_rebase(session_id, summary["start"])

    # Regression check: failed rebase must not poison the session.
    assert real_backend.binary_summary(session_id)["session_id"] == session_id


def test_rebase_same_base_is_noop(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, _, _ = _open_analyzed(real_backend, sample_binary_path)
    summary = real_backend.binary_summary(session_id)

    rebased = real_backend.loader_rebase(session_id, summary["start"])
    assert rebased["rebased"] is False
    assert rebased["start"] == summary["start"]


def test_rebase_blocked_while_async_task_active(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id = _open_rw(real_backend, sample_binary_path)
    summary = real_backend.binary_summary(session_id)

    task_id = "pending-task"
    real_backend._tasks[task_id] = TaskRecord(
        task_id=task_id,
        kind="analysis.update_and_wait",
        future=Future(),
        session_id=session_id,
    )
    try:
        with pytest.raises(BinjaBackendError, match="while async tasks are active"):
            real_backend.loader_rebase(session_id, summary["start"])
    finally:
        real_backend._tasks.pop(task_id, None)


def test_find_function_containing_uses_safe_fallback_call(real_backend: BinjaBackend) -> None:
    class DummyView:
        def __init__(self, function: object):
            self._function = function

        def get_function_at(self, address: int) -> object | None:
            if address == 0x1234:
                return self._function
            return None

    sentinel_function = object()
    dummy_view = DummyView(sentinel_function)

    found = real_backend._find_function_containing(dummy_view, 0x1234)
    assert found is sentinel_function


def test_database_read_global_reports_exception_type(
    real_backend: BinjaBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyMessageError(RuntimeError):
        def __str__(self) -> str:
            return ""

    class DummyDatabase:
        global_keys: ClassVar[list[str]] = ["mcp.key"]

        def read_global(self, _key: str) -> str:
            raise EmptyMessageError()

    monkeypatch.setattr(real_backend, "_get_database", lambda _: DummyDatabase())
    with pytest.raises(BinjaBackendError, match="EmptyMessageError"):
        real_backend.database_read_global("test-session", "mcp.key")


def test_database_read_global_reports_key_not_found(
    real_backend: BinjaBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DummyDatabase:
        def __init__(self) -> None:
            self.read_called = False
            self.global_keys = ["known.key"]

        def read_global(self, _key: str) -> str:
            self.read_called = True
            raise AssertionError()

    database = DummyDatabase()
    monkeypatch.setattr(real_backend, "_get_database", lambda _: database)
    with pytest.raises(BinjaBackendError, match=r"database global key not found: missing\.key"):
        real_backend.database_read_global("test-session", "missing.key")
    assert database.read_called is False


def test_annotations_and_metadata(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id, main_start, _ = _open_analyzed(real_backend, sample_binary_path)
    search = real_backend.search_text(session_id, "Hello", limit=5)
    hello_addr = search["items"][0]["address"]

    renamed_function = real_backend.rename_function(session_id, main_start, "main_mcp_test")
    assert renamed_function["function"]["name"] == "main_mcp_test"

    renamed_symbol = real_backend.rename_symbol(session_id, main_start, "main_symbol_test")
    assert renamed_symbol["symbol"]["name"] == "main_symbol_test"

    defined_symbol = real_backend.define_symbol(
        session_id,
        main_start,
        "main_defined_symbol",
        symbol_type="FunctionSymbol",
    )
    assert defined_symbol["symbol"]["name"] == "main_defined_symbol"

    assert real_backend.undefine_symbol(session_id, main_start)["undefined"] is True

    renamed_data = real_backend.rename_data_var(session_id, hello_addr, "hello_data_var")
    assert renamed_data["data_var"]["name"] == "hello_data_var"

    defined_data = real_backend.define_data_var(
        session_id,
        hello_addr,
        type_name="char",
        width=1,
        name="hello_data_var_2",
    )
    assert defined_data["data_var"]["address"].startswith("0x")

    assert real_backend.undefine_data_var(session_id, hello_addr)["undefined"] is True

    set_comment = real_backend.set_comment(session_id, main_start, "backend test comment")
    assert set_comment["comment"] == "backend test comment"
    assert real_backend.get_comment(session_id, main_start)["comment"] == "backend test comment"

    tags = real_backend.add_tag(session_id, main_start, "mcp-test", "tag-data", icon="M")
    assert tags["count"] >= 1
    assert real_backend.get_tags_at(session_id, main_start)["count"] >= 1

    stored = real_backend.metadata_store(session_id, "mcp.key", {"k": "v"})
    assert stored["value"]["k"] == "v"
    assert real_backend.metadata_query(session_id, "mcp.key")["value"]["k"] == "v"
    assert real_backend.metadata_remove(session_id, "mcp.key")["removed"] is True


def test_patch_and_undo_features(real_backend: BinjaBackend, sample_binary_path: str) -> None:
    session_id, main_start, main_start_int = _open_analyzed(real_backend, sample_binary_path)

    assembled = real_backend.patch_assemble(session_id, main_start, "nop")
    assert assembled["written"] >= 1

    patch_addr = _find_patch_address(
        real_backend,
        session_id,
        main_start_int,
        main_start_int + 0x60,
    )
    assert real_backend.patch_status(session_id, patch_addr)["address"].startswith("0x")

    tx = real_backend.undo_begin(session_id)["transaction_id"]
    real_backend.patch_convert_to_nop(session_id, patch_addr)
    real_backend.patch_always_branch(session_id, patch_addr)
    real_backend.patch_never_branch(session_id, patch_addr)
    real_backend.patch_invert_branch(session_id, patch_addr)
    real_backend.patch_skip_and_return_value(session_id, patch_addr, 7)
    real_backend.undo_revert(session_id, tx)

    tx2 = real_backend.undo_begin(session_id)["transaction_id"]
    real_backend.set_comment(session_id, main_start, "undo-commit-comment")
    real_backend.undo_commit(session_id, tx2)
    real_backend.undo(session_id)
    real_backend.redo(session_id)
