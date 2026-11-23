MemTrace 观测台 — 交付源码与配置（与线上部署逐字节一致）

src/public/        应用源码（index.php 首页、info.php 巡检面板、healthz.php）
src/conf/          PHP 运行基线 hardening.ini、Apache prefork 配置 prefork.conf
src/site/          Apache 站点与请求过滤器 memtrace.conf（蓝队加固规则全部在此）
src/gateway/       请求规范化网关 gw.py（Python 标准库）：固定头部形状转发 + 蓝队固定串过滤
src/Dockerfile     Apache+mod_php 镜像构建（基础镜像 php:8.5.11-apache）

入口链路：客户端 → 规范化网关（过滤 + 规范化）→ Apache prefork 单 worker + mod_php。
台面没有其他隐藏组件；所有行为都能在这份源码与配置里解释。
