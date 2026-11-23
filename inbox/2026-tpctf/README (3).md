# QwirlBox attachments

Everything needed to rebuild the exact engine binary that runs on the
challenge box:

- `quickjs-base-bundle.tar.gz` — the pristine QuickJS `2026-06-04` baseline
  bundle: full engine source under `third_party/quickjs/src/`, the fixed TCP
  adapter (`adapter/server.py`), the fixed host loader
  (`runner/qjs_runner.c`), `Makefile`, `Dockerfile` and docs.
  SHA-256: `a69e0f7f77c5714909c36e661861e1c685ec135ec9063a5b1dd3943449aa8d7c`

- `patch.diff` — the only difference between the baseline and the deployed
  engine build. Apply it inside the extracted bundle:

```sh
tar xzf quickjs-base-bundle.tar.gz
cd quickjs-base-bundle        # or the directory the bundle extracted to
patch -p1 < ../patch.diff
make -j"$(nproc)" runner      # gcc, flags are pinned in the Makefile
```

The deployed service runs the runner built exactly this way (Debian
bookworm gcc, `-O2 -g`, later stripped for size; stripping does not change
behaviour). The runner binary served by the image:

```
SHA-256: ce64501fa4ff52d132fe761291d59c366e810629ce53a7a505cbfdc7146d1716
```

Nothing about the challenge is hidden: the defence rests entirely on the
memory-safety work past the public patch, not on secret sources.

To run the whole service locally:

```sh
python3 adapter/server.py --host 127.0.0.1 --port 8000 \
  --runner ./build/qjs_runner --flag-file /path/to/flag
```

Then talk JSON Lines to it:

```sh
printf '{"code":"1+1"}\n' | nc 127.0.0.1 8000
```
