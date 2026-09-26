# Binary Canvas

Private, client-side PE and ELF explorer. Drop an executable into the browser and inspect its structure without uploading it anywhere.

## Live demo

https://z4tm.github.io/binary-canvas/

## Features

- PE32, PE32+, ELF32 and ELF64 header parsing
- x86, x86-64, ARM, AArch64 and RISC-V identification
- section table with file offsets, addresses, flags and entropy
- interactive entropy map linked to the hex view
- printable string extraction and filtering
- SHA-256 fingerprinting through Web Crypto
- local-only processing with no backend and no tracking
- zero runtime dependencies

## Development

```bash
npm install
npm test
npm run build
```

Open `index.html` through any static HTTP server after building:

```bash
python -m http.server 8080
```

## Privacy

Files never leave the browser. The page has no upload endpoint, analytics script or application server.
