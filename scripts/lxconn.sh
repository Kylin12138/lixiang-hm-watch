#!/bin/bash
# 手表无线调试端口每次重连都会变，这里自动找可用端口
# 用法：source scripts/lxconn.sh   （导出 LX_HDC / LX_T）
#
# 需要先告诉脚本手表 IP：在 scripts/local.env 里写 LX_WATCH_IP=192.168.1.x
# （local.env 已被 .gitignore 忽略，不会进仓库）

_here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ -f "$_here/local.env" ]; then
  # shellcheck disable=SC1091
  . "$_here/local.env"
fi

if [ -z "${LX_WATCH_IP:-}" ]; then
  echo "✗ 未设置手表 IP。请在 scripts/local.env 写入：LX_WATCH_IP=192.168.1.100" >&2
  return 1 2>/dev/null || exit 1
fi

# hdc 位置：优先环境变量，其次 DevEco 默认安装路径
HDC="${HDC_BIN:-${DEVECO_HOME:-/c/Program Files/Huawei/DevEco Studio}/sdk/default/openharmony/toolchains/hdc.exe}"
IP="$LX_WATCH_IP"

probe() {
  local p="$1"
  local r
  r=$(MSYS_NO_PATHCONV=1 timeout 6 "$HDC" tconn "$IP:$p" 2>&1 | tr -d '\r')
  case "$r" in
    *"Connect OK"*) echo "$IP:$p"; return 0;;
    *"repeat operation"*) echo "$IP:$p"; return 0;;
  esac
  return 1
}

find_target() {
  # 1) 先试已知/列出的端口
  local ports
  ports=$("$HDC" list targets 2>&1 | tr -d '\r' | awk -v ip="$IP" '$1 ~ ip":" {split($1,a,":"); print a[2]}' | sort -u)
  local p
  for p in $ports ${LX_EXTRA_PORTS}; do
    local t
    if t=$(probe "$p"); then echo "$t"; return 0; fi
  done
  return 1
}

export LX_HDC="$HDC"
export LX_T="$(find_target)"
if [ -n "$LX_T" ]; then
  echo "TARGET=$LX_T"
  # ★ 连上后立刻延长熄屏时间（30 分钟）——手表熄屏会断无线调试
  MSYS_NO_PATHCONV=1 "$HDC" -t "$LX_T" shell "power-shell timeout -o 1800000" >/dev/null 2>&1
else
  echo "TARGET=none"
fi
