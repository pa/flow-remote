# Vendored code

Pinned copies, served from our own origin so the page runs no script from
a CDN. The phone's signing key can't be exported, but any script on the
page could use it, so each file here was checked against npm's published
integrity hash before it was copied in.

| Directory | Package | License | npm integrity of the tarball |
| --- | --- | --- | --- |
| jsqr-1.4.0 | jsqr@1.4.0, `dist/jsQR.js` | Apache-2.0 | sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A== |

To update, run `npm pack <pkg>@<version>`, compare its sha512 with
`npm view <pkg>@<version> dist.integrity`, copy the files, and update this table.
