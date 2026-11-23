# UpWatch 附件

部署即所见：这台看板没有任何隐藏配置。

- `public/` — 看板全部源码（index.php / upload.php / view.php / healthz.php）。
- `zz-hard.ini` — 服务器实际加载的 PHP 配置（`/usr/local/etc/php/conf.d/zz-hard.ini`）。
- `prefork.conf` — Apache prefork 配置（`/etc/apache2/mods-available/mpm_prefork.conf`）。

服务器：平台预置 `php:8.5.11-apache`（Apache 2.4.69 + mod_php）。

把文件交给看板，找回它真正保管的东西。
