PixelBoard 附件说明

本目录是题目运行环境的完整源码与配置，供选手审计：

  app/site/index.php        看板应用源码
  app/conf/zz-app.ini       PHP 运行配置
  app/conf/mpm_prefork.conf Apache prefork 配置
  app/conf/srv.conf         站点目录授权
  app/Dockerfile.txt        镜像构建文件（原文为 services/app/Dockerfile）
  docker-compose.txt        服务编排（原文为 docker-compose.yml，入口 URL 由平台下发）

镜像基于平台预置的 php:8.5.11-apache，未做二进制层面的修改。
动态 flag 由平台注入，不在本附件中。

  gate/gate.py             前置 WAF 源码（入口；规则见 gate/README.md）
