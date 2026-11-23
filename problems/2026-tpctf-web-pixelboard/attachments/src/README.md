# Front gate

`gate.py` runs as the entry service. The application listens only on the internal
network.

Request contract, enforced by the gate:

- state-changing requests carry `X-Panel: pixelboard`;
- a request body carries a valid `Content-Length` (no `Transfer-Encoding`);
- a state-changing request carries the value of `X-Handshake` that `GET /handshake` returns;
- multipart bodies use at most 1200 parts; a body is at most 16 MiB;
- the multipart boundaries used by the published reference exploit are refused.

The gate adds `X-Powered-By: PHP/8.4.26` to responses. The deployed image and its
version are stated in the source material shipped with this challenge.
