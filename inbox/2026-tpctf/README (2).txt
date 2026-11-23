# jsbox — QuickJS 引擎内存迷宫（题面）

## 服务

一个基于 QuickJS 引擎（2026-06-04 发行版）的 JavaScript 求值服务：

- 通过 TCP 连接服务端口，发送单行 JSON 请求 `{"code": "<JS 源码>"}`；
- 服务返回 `{"ok": true, "result": ...}` 或 `{"ok": false, "error": ...}`；
- 同一 TCP 连接内 JS 运行时状态保留（globalThis 持久），断开连接后
  该 worker 进程被销毁；
- 源码上限 64 KiB，每次求值默认超时 2 秒；
- 引擎运行时已剥离文件、环境变量、进程管理、`std`/`os`、原生模块
  加载及外部网络等全部敏感 API。

## 目标

每个运行实例启动时会注入一个只存在于 worker 进程内存中的动态
flag（环境变量 `QJS_CTF_FLAG`）。通过分析引擎实现、发现并利用其中
的内存安全缺陷，把 flag 从进程内存中取回来。

## 附件（完全白盒，无任何隐藏）

- `quickjs-base-bundle.tar.gz` — 完整的 QuickJS 2026-06-04 底座源码包
  （含 `third_party/quickjs/` 引擎源码树、`adapter/server.py`、
  `runner/qjs_runner.c`、`Makefile`、`Dockerfile` 与协议说明）。
- `patch.diff` — 与线上运行二进制完全一致的引擎补丁。线上服务的
  `qjs_runner` 由底座源码应用该补丁后编译而成。

题目难度完全来自补丁所引入的内存安全缺陷本身的利用复杂度，不存在
隐藏源码、抹除符号或暗桩猜谜。

## 环境

- linux/amd64 容器部署，服务监听容器内 8000 端口；
- 运行期无任何公网访问；
- flag 由平台按实例动态生成，只读挂载注入，不与源码一同分发。
