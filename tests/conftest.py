from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.server import SimpleMcpServer


@pytest.fixture
def sample_binary_path() -> str:
    fixtures = Path(__file__).resolve().parent / "fixtures"
    source_path = fixtures / "hello.c"
    binary_path = fixtures / "hello"

    if not source_path.exists():
        pytest.skip(f"sample source does not exist: {source_path}")

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler found (cc/gcc/clang)")

    if not binary_path.exists() or binary_path.stat().st_mtime < source_path.stat().st_mtime:
        subprocess.run(
            [compiler, str(source_path), "-O0", "-g", "-fno-inline", "-o", str(binary_path)],
            check=True,
        )

    return str(binary_path)


@pytest.fixture
def real_backend() -> BinjaBackend:
    binaryninja = pytest.importorskip("binaryninja")
    backend = BinjaBackend(binaryninja)
    yield backend
    backend.shutdown()


@pytest.fixture
def real_server(real_backend: BinjaBackend) -> SimpleMcpServer:
    return SimpleMcpServer(real_backend)
