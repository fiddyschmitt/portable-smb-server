# portable-smb-server

A portable SMB server: a single executable, runs without admin rights,
and has no dependencies.

## Features

- SMB dialects 2.0.2, 2.1, 3.0, 3.0.2
- NTLMv2 authentication with message signing (HMAC-SHA256 on 2.x, AES-CMAC on
  3.x), or guest access with `-guest`
- Multiple shares
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
  -share NAME     share name for the preceding -folder (default: folder's base name)
  -log FILE       also write the log to this file
  -v              verbose (per-request) logging
```

Shares are passed as `-folder`/`-share` pairs; `-share` names the `-folder`
before it and may be omitted:

```
portable-smb-server -folder "D:\Temp" -share "temp" -folder "D:\Photos"
```

exports `\\HOST\temp` and `\\HOST\Photos`. Unnamed folders default to their
base name; if two unnamed folders share a base name they deconflict by
flattening the path (`-folder D:\Temp -folder E:\Temp` becomes `d_temp` and
`e_temp`). With no `-folder` at all, the current directory is exported as
`data`.

The default port is 1445 rather than the standard 445 so the server can run
without admin rights and without clashing with a system SMB service.

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

Note: recent Windows clients reject guest (unauthenticated) sessions because
they cannot be signed — use `-user`/`-pass` for Windows clients. Linux and
macOS clients can use `-guest`.

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
