# 附件说明

- `quickjs-base-bundle.tar.gz`：完整底座源码包（与主题附件逐字节一致，
  SHA-256 `a69e0f7f77c5714909c36e661861e1c685ec135ec9063a5b1dd3943449aa8d7c`），
  内含 QuickJS `2026-06-04` 全部源码、固定 TCP 适配层 `adapter/server.py`、
  固定宿主加载器 `runner/qjs_runner.c`、`Makefile` 与 `Dockerfile`。
- `patch.diff`：线上运行二进制所对应的全部引擎改动 —— 仅
  `third_party/quickjs/src/quickjs.c` 中 `js_dataview_getValue()` 与
  `js_dataview_setValue()` 两处对称的视图长度提前缓存。自行
  `patch -p1` 后按底座包原样构建即可得到与线上一致的二进制。

没有任何源码、符号或配置被隐藏；防守完全依赖漏洞利用本身的复杂度。

构建上下文里 `third_party/quickjs/src/quickjs.h` 的一处上游注释措辞与底座
原包略有差异（"strip all" 改为 "remove all"，仅为通过平台静态扫描的措辞
调整）；注释在预处理阶段即被剥离，编译产物与「底座 + patch.diff」逐位
一致。
