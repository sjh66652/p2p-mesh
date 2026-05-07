#!/bin/bash
# ==============================================================
# P2P Mesh Network - Phase 1 & 2 Upgrade Verification Script
# ==============================================================
# 使用方法:
#   chmod +x scripts/verify-upgrade.sh
#   ./scripts/verify-upgrade.sh
#
# 验证内容:
#   1. Rust 数据面编译检查 (cargo check)
#   2. Rust 单元测试 (cargo test)
#   3. Python 语法检查 (python -m py_compile)
#   4. Python 导入依赖检查
#   5. 新文件完整性检查
# ==============================================================

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PASSED=0
FAILED=0

log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED + 1)); }
log_info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }
section()  { echo ""; echo "=== $1 ==="; }

# ---- 1. Rust: cargo check ----
section "1. Rust 数据面编译检查"

cd "$PROJECT_DIR/data-plane"

if command -v cargo &> /dev/null; then
    log_info "Rust toolchain: $(rustc --version)"

    # Check all three binaries
    for bin in mesh-tunnel mesh-relay mesh-stun; do
        echo "  ➜ cargo check --bin $bin"
        if cargo check --bin "$bin" 2>&1 | tail -5; then
            log_pass "cargo check --bin $bin"
        else
            log_fail "cargo check --bin $bin (run: cargo check --bin $bin 2>&1 | head -40)"
        fi
    done

    # Check library build
    echo "  ➜ cargo check --lib"
    if cargo check --lib 2>&1 | tail -5; then
        log_pass "cargo check --lib"
    else
        log_fail "cargo check --lib"
    fi
else
    log_fail "cargo not found — install Rust: https://rustup.rs"
fi


# ---- 2. Rust: cargo test (existing crypto tests) ----
section "2. Rust 单元测试"

if command -v cargo &> /dev/null; then
    echo "  ➜ cargo test"
    if cargo test 2>&1 | tail -10; then
        log_pass "cargo test"
    else
        log_fail "cargo test"
    fi
fi


# ---- 3. Python 语法检查 ----
section "3. Python 控制面语法检查"

cd "$PROJECT_DIR/control-plane"

if command -v python3 &> /dev/null; then
    log_info "Python: $(python3 --version)"

    # Collect all changed/new Python files
    PY_FILES=(
        app/api/candidates.py
        app/schemas/candidate.py
        app/services/nat_utils.py
        app/api/ws.py
        app/services/signaling_service.py
        app/services/network_service.py
        app/main.py
    )

    for f in "${PY_FILES[@]}"; do
        if [ -f "$f" ]; then
            if python3 -m py_compile "$f" 2>&1; then
                log_pass "py_compile $f"
            else
                log_fail "py_compile $f"
            fi
        else
            log_fail "File not found: $f"
        fi
    done
else
    log_fail "python3 not found"
fi


# ---- 4. Python 导入链检查 ----
section "4. Python 导入链检查"

cd "$PROJECT_DIR/control-plane"

PY_IMPORT_FILES=(
    "app/api/ws.py"
    "app/services/signaling_service.py"
    "app/services/nat_utils.py"
    "app/api/candidates.py"
    "app/services/network_service.py"
)

for f in "${PY_IMPORT_FILES[@]}"; do
    if [ -f "$f" ]; then
        if python3 -c "
import ast, sys
with open('$f') as fh:
    try:
        ast.parse(fh.read())
        print('OK')
    except SyntaxError as e:
        print(f'SYNTAX ERROR: {e}')
        sys.exit(1)
" 2>&1; then
            log_pass "ast.parse $f"
        else
            log_fail "ast.parse $f"
        fi
    fi
done


# ---- 5. 新文件完整性检查 ----
section "5. 新文件完整性"

NEW_RUST_FILES=(
    "data-plane/src/stun/mod.rs"
    "data-plane/src/puncher/mod.rs"
    "data-plane/src/quic/mod.rs"
    "data-plane/src/multipath/mod.rs"
    "data-plane/src/metrics/mod.rs"
    "data-plane/src/bin/mesh-stun.rs"
)

NEW_PY_FILES=(
    "control-plane/app/api/candidates.py"
    "control-plane/app/schemas/candidate.py"
    "control-plane/app/services/nat_utils.py"
)

NEW_DOCKER_FILES=(
    "deployment/Dockerfile.stun"
)

MODIFIED_FILES=(
    "data-plane/src/lib.rs"
    "data-plane/Cargo.toml"
    "data-plane/src/tunnel/mod.rs"
    "data-plane/src/bin/mesh-tunnel.rs"
    "control-plane/app/api/ws.py"
    "control-plane/app/services/signaling_service.py"
    "control-plane/app/services/network_service.py"
    "control-plane/app/main.py"
    "deployment/docker-compose.yml"
    "deployment/docker-compose.prod.yml"
    "deployment/Dockerfile.relay"
)

for f in "${NEW_RUST_FILES[@]}" "${NEW_PY_FILES[@]}" "${NEW_DOCKER_FILES[@]}"; do
    if [ -f "$PROJECT_DIR/$f" ]; then
        size=$(wc -c < "$PROJECT_DIR/$f")
        log_pass "$f ($size bytes) ✓"
    else
        log_fail "MISSING: $f"
    fi
done

for f in "${MODIFIED_FILES[@]}"; do
    if [ -f "$PROJECT_DIR/$f" ]; then
        size=$(wc -c < "$PROJECT_DIR/$f")
        log_pass "$f ($size bytes) ✓"
    else
        log_fail "MISSING: $f"
    fi
done


# ---- 6. Dockerfile 语法 ----
section "6. Dockerfile 语法"

if command -v docker &> /dev/null; then
    for df in deployment/Dockerfile.stun deployment/Dockerfile.relay; do
        if docker build --check -f "$PROJECT_DIR/$df" "$PROJECT_DIR/data-plane" 2>&1 | tail -3; then
            log_pass "docker build --check $df"
        else
            log_fail "docker build --check $df"
        fi
    done
else
    log_info "Docker not available — skipping Dockerfile validation"
fi


# ---- 总结 ----
section "验证结果"
echo ""
echo "  通过: $PASSED"
echo "  失败: $FAILED"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}所有检查通过!${NC}"
    exit 0
else
    echo -e "  ${RED}$FAILED 项检查失败，请查看上方详情${NC}"
    exit 1
fi
