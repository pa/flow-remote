# Vendored code

Pinned copies, served from our own origin so the page runs no script from
a CDN. The phone's signing key can't be exported, but any script on the
page could use it, so each file here was checked against npm's published
integrity hash before it was copied in.

| Directory | Package | License | npm integrity of the tarball |
| --- | --- | --- | --- |
| firebase-12.19.0 | firebase@12.19.0, `firebase-app.js` and `firebase-auth.js` | Apache-2.0 | sha512-kwXCLcI0ly2lkwygkbuRx6SsX3DSO96355YrWh9SWZ5ncsxK/y5cirn3sY6nZVSiBVE++2nL6Hchzu1EB8uohQ== |
| jsqr-1.4.0 | jsqr@1.4.0, `dist/jsQR.js` | Apache-2.0 | sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A== |

One edit: `firebase-auth.js` imports `firebase-app.js` from
`https://www.gstatic.com/firebasejs/12.19.0/`, and that import is rewritten
to `./firebase-app.js`. The gstatic URLs left in `firebase-app.js` are
name strings for its logger, not imports.

To update, run `npm pack <pkg>@<version>`, compare its sha512 with
`npm view <pkg>@<version> dist.integrity`, copy the files, and update this table.
