# LedgerPad — player handout

This directory is the parts of the deployment you are meant to read: the
service code and every configuration value the worker was started with.

## Files

| path | what it is |
|---|---|
| `app/index.php` | the ticket-drop page served at `/index.php` |
| `config/php.ini` | the PHP worker profile (`conf.d/zz-harden.ini` inside the image) |
| `config/prefork.conf` | Apache MPM prefork configuration (`mpm_prefork.conf`) |
| `config/zz-body.conf` | Apache request-body cap (`conf.d/zz-body.conf`) |

## The deployment, as configured

- base image: `php:8.5.11-apache` (PHP 8.5.11, Apache 2.4.69, Debian trixie)
- the document root is `/var/www/html`, writable by the worker account; `/x`
  is a short symlink to it
- one prefork worker, no keep-alive; the worker stays warm between requests
- `memory_limit=16M`, `post_max_size=8M`, `upload_max_filesize=8M`
- Apache refuses request bodies above 8 MiB (`LimitRequestBody`)
- session upload progress stays enabled; the app never calls `session_start()`
- the deployment's answer file is `/flag`, readable by the worker account

## About this challenge (author's note — spoiler-free)

The designer's note for reviewers and solvers: this box is built around the
PHP request-lifecycle memory-safety class published as CVE-2026-109618 and
CVE-2026-109619 ("PHP2Shell"). The public proof-of-concept for that class is
available at <https://github.com/alvarodh5/php2shell> and is expected to be
in your toolbox. It does **not** work here unchanged: this deployment's body
caps block the proof-of-concept's own out-of-memory strategy, and shaping a
request chain that still reaches the vulnerable worker state within an 8 MiB
body is part of the challenge. Every source file and configuration value you
need is in this directory; nothing about the trigger is hidden.
