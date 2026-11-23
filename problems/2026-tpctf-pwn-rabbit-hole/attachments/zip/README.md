# 附件说明

- `quickjs-base-bundle.tar.gz`：官方下发的 QuickJS `2026-06-04` 固定底座源码包
  （SHA-256 `a69e0f7f77c5714909c36e661861e1c685ec135ec9063a5b1dd3943449aa8d7c`，
  与主题附件完全一致），含 `adapter/server.py`、`runner/qjs_runner.c`、`Makefile`
  与原始 Dockerfile。
- `patch.diff`：与线上运行二进制**完全一致**的引擎增量补丁，仅改动
  `third_party/quickjs/src/quickjs.c` 一处；adapter、runner、协议未做任何修改。

## 本地复现线上二进制

```sh
sha256sum quickjs-base-bundle.tar.gz   # 应为上述值
mkdir base && tar xzf quickjs-base-bundle.tar.gz -C base
cd base && patch -p1 < ../patch.diff
make runner -j"$(nproc)" CFLAGS="-O2" LDFLAGS="-static"   # 静态链接，产物 build/qjs_runner
python3 adapter/server.py --host 127.0.0.1 --port 8000 \
  --runner ./build/qjs_runner --flag-file /path/to/flag
```

线上镜像为 `python:3.12-slim-bookworm` + 预编译静态 `qjs_runner`（构建期零安装、
零网络），可用上述步骤验证二进制一致性（引擎源码、编译选项均未再改动）。
