# portable-smb-server

A portable SMB server: a single executable, runs without admin rights,
and has no dependencies.

## Download

Executables for Windows, Linux and Mac can be found over in the [releases](https://github.com/fiddyschmitt/portable-smb-server/releases/latest) section.

## Features

- SMB dialects 2.0.2, 2.1, 3.0, 3.0.2
- NTLMv2 authentication with message signing (HMAC-SHA256 on 2.x, AES-CMAC on 3.x), or guest access with `-guest`
- Multiple shares, each backed by a local folder (`-folder`) or an external VFS provider service (`-vfs`, see below)
- Read-only shares (`-readonly`, or declared by the provider)
- Works with the native SMB clients on Windows, Linux (cifs) and macOS

## Usage

```
portable-smb-server [flags]

  -ip string      IP address to bind to (default "127.0.0.1")
  -port int       TCP port to bind to (default 1445)
  -user string    username for NTLM authentication (default "user")
  -pass string    password for NTLM authentication (default "password")
  -guest          allow unauthenticated guest access (ignores -user/-pass)
  -folder DIR     folder to share; repeatable (default: current directory)
  -vfs URL        external VFS provider to share; repeatable (see "Bring your own VFS")
  -share NAME     share name for the preceding -folder or -vfs (default: folder base name / provider's suggestion)
  -readonly       expose every share read-only
  -openapi ADDR   also serve the VFS provider OpenAPI spec (Swagger UI) on this address
  -log FILE       also write the log to this file
  -v              verbose (per-request) logging
```

Shares are passed as `-folder`/`-share` pairs; `-share` names the `-folder`
before it and may be omitted:

```
portable-smb-server -folder "D:\Temp" -share "temp" -folder "D:\Photos"
```

exports `\\HOST\temp` and `\\HOST\Photos`. Unnamed folders default to their
base name.

The default port is 1445 rather than the standard 445 so the server can run
without admin rights and without clashing with a system SMB service.

## Bring your own VFS

An external program — in any language — can provide the files behind a share:
file lists, file contents and *sub-file* contents (ranged reads), plus the
write operations if it wants to be writable. It just implements a small HTTP
service against the OpenAPI contract this server ships:

```
portable-smb-server -openapi 127.0.0.1:8081
# browse http://127.0.0.1:8081/ (Swagger UI) or fetch /openapi.json for codegen
```

Then point a share at it (mixes freely with -folder shares):

```
portable-smb-server -vfs http://127.0.0.1:9000 -share cloud -folder "D:\Local"
```

The provider implements `GET /stat`, `GET /list` and `GET /read?offset&length`
(that's enough for a read-only share) and optionally `/create`, `/write`,
`/mkdir`, `/rename`, `/remove`, `/truncate`, `/chtimes` for writes, plus
`GET /capabilities` to suggest a share name and declare `readOnly` /
`caseInsensitive`. Read-only can be enforced from either side: the provider's
`readOnly` capability, or `-readonly` on this server (clients see
`STATUS_MEDIA_WRITE_PROTECTED` and a read-only volume).

`examples/localvfs` is a complete reference provider (~100 lines of handler
code) that serves a local folder over the contract:

```
go run ./examples/localvfs -folder "D:\Data" -addr 127.0.0.1:9000
portable-smb-server -vfs http://127.0.0.1:9000
```

## Connecting

Windows 11 (custom port needs the `/TCPPORT` option):

```
net use X: \\HOST\data /TCPPORT:1445 /USER:user password
```

Linux:

```
sudo mount -t cifs //HOST/data /mnt -o port=1445,vers=3.0,user=user,pass=password
smbclient //HOST/data -p 1445 -U user%password
```

macOS (Finder → Go → Connect to Server):

```
smb://user@HOST:1445/data
```

## Building

```
.\build.ps1        # win-x64, linux-x64, linux-arm64, osx-x64, osx-arm64 into .\bin\
go test ./...      # unit tests (protocol + backend)
```

The e2e tests live in a separate Go module (`test/`) so the product module
stays dependency-free; they drive the server with a real SMB2 client:

```
cd test; go test
```
