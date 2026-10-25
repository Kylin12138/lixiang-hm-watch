#!/usr/bin/env bash
# 在电脑上构建 / 预览 LixiangWatch 的环境准备脚本
# 用法：source scripts/env.sh
#
# ★ 必需的环境变量（缺任一个都会报错）：
#   DEVECO_SDK_HOME —— SDK 根，否则 hvigor 报 00303217
#   JAVA_HOME       —— jbr，否则打包阶段报 `spawn java ENOENT` / 00308018
#
# 注意：PATH 里要加【POSIX 路径 /c/...】而不是 Windows 路径 C:/...
#      因为 hvigor 用 child_process.spawn 调 java，走的是 Windows PATH。
#
# 个性化配置：把本机路径 / 手表 IP 写进 scripts/local.env（已被 .gitignore 忽略），
#             本脚本会自动加载，避免把个人环境提交到仓库。

_here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# 本地私有配置（可选，不入库）
if [ -f "$_here/local.env" ]; then
  # shellcheck disable=SC1091
  . "$_here/local.env"
fi

# DevEco Studio 安装位置：优先取环境变量，否则用各平台默认值
# ★ Windows 下必须是 C:/ 盘符风格（hvigor 是 node 程序，不认 /c/... 这种 MSYS 路径）
if [ -z "${DEVECO_HOME:-}" ]; then
  for _cand in \
    "C:/Program Files/Huawei/DevEco Studio" \
    "/Applications/DevEco-Studio.app/Contents" \
    "$HOME/Applications/DevEco Studio.app/Contents"
  do
    if [ -d "$_cand" ]; then DEVECO_HOME="$_cand"; break; fi
  done
fi
if [ -z "${DEVECO_HOME:-}" ]; then
  echo "✗ 找不到 DevEco Studio。请在 scripts/local.env 里设置 DEVECO_HOME=/你的安装路径" >&2
  return 1 2>/dev/null || exit 1
fi
export DEVECO_HOME

export DEVECO_SDK_HOME="$DEVECO_HOME/sdk"
export JAVA_HOME="$DEVECO_HOME/jbr"
export NODE_HOME="$DEVECO_HOME/tools/node"
export HVIGOR_BIN="$DEVECO_HOME/tools/hvigor/bin/hvigorw.js"
export OHPM_HOME="$DEVECO_HOME/tools/ohpm/bin"
export PREVIEWER_BIN="$DEVECO_HOME/sdk/default/openharmony/previewer/common/bin/Previewer.exe"

# ★ 必须把 jbr/bin 加进 PATH：hvigor 用 child_process.spawn 调 java，
#   只认 PATH 不认 JAVA_HOME。PATH 里要用 POSIX 风格（/c/...），
#   这里用 cygpath 把 C:/... 转一下；没有 cygpath 的环境（真 Linux/macOS）直接用原值。
_jbr_posix="$(cygpath -u "$JAVA_HOME" 2>/dev/null || echo "$JAVA_HOME")"
export PATH="$_jbr_posix/bin:$NODE_HOME:$PATH"

# 工程根（含 hvigor/hvigor-config.json5 的那一层）
# ★ hvigor 必须在工程根执行，否则报 00304004 Not Found
export PROJ="$(cd "$_here/../LixiangWatch" && pwd)"

# 便捷函数
# ★ hvigor 必须在【工程根】执行（含 hvigor/hvigor-config.json5 那层），
#   用 --project-dir 或外部 cd 都行，这里直接 cd 最稳。
lxbuild() {
  ( cd "$PROJ" && node "$HVIGOR_BIN" assembleHap --mode module \
      -p product=default --no-daemon "$@" )
}
lxclean() {
  ( cd "$PROJ" && node "$HVIGOR_BIN" clean --no-daemon "$@" )
}
# 产物路径
lxhap() {
  echo "$PROJ/entry/build/default/outputs/default/entry-default-unsigned.hap"
}

echo "DEVECO_SDK_HOME = $DEVECO_SDK_HOME"
echo "JAVA_HOME       = $JAVA_HOME"
echo "node            = $(node --version 2>/dev/null || echo '未加入 PATH')"
echo "hvigor          = $HVIGOR_BIN"
echo "previewer       = $PREVIEWER_BIN"
echo "可用命令：lxbuild / lxclean / lxhap"
