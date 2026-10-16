# The rig tests: real clients, real machines, every pair

`test/rig` runs portable-smb-server against the operating systems' own SMB clients on a rig of
six machines, two per OS: Windows 11 (`net use`), Debian 13 (`mount -t cifs`, and Samba's
`smbclient`) and macOS (`mount_smbfs`, the one client that negotiates Apple's SMB2 extensions).
The server under test runs on one machine and the client on another, for every client OS x server
OS pair, so every row is two machines on a LAN.

The machines are defined as code beside the repo, in `portable-smb-server local\provisioning`
(Vagrant + Ansible for the VirtualBox VMs, Vagrant + tart for the macOS VM, and the Mac itself);
its README says how to build them. The tests read that folder's `settings.yml` for the machines
(or `$PSMB_RIG_DIR`); without it, or when a machine is unreachable, they skip rather than fail.
The loopback tests in `test/` need no rig and are what `go test ./...` runs; these are run on
purpose:

    cd test
    go test ./rig -run TestMatrix -v -timeout 3h                  # every pair x every condition
    go test ./rig -run 'TestMatrix/linux->windows' -v              # one pair (client->server)
    go test ./rig -run 'TestMatrix/.*/rename' -v                   # one condition, every pair
    PSMB_PAIRS="macos>linux,linux>macos" go test ./rig -run TestMatrix -v
    go test ./rig -run TestMultiClient -v                          # every client at once, per server
    PSMB_STRESS_SECONDS=300 go test ./rig -run TestStress -v -timeout 2h

`TestMain` cross-compiles the server, the `localvfs` example provider and the `psmbstress` load
generator (`test/rig/worker`) for linux/amd64, windows/amd64 and darwin/arm64, and the tests push
them to the machines (skipping uploads whose SHA-256 the machine already has). Every run writes a
report to `portable-smb-server local\results\`.

## TestMatrix: the conditions

For each pair the server is started three times (the standard server with four shares; a `-guest`
server; a `-readonly` server) and each condition is a subtest, so one failure never hides the next.
Every condition that writes checks the bytes on both ends: what the client reads back, and what is
in the server's backing directory.

| Condition | What it exercises |
|---|---|
| `roundtrip_4mib`, `empty_file` | write, read back, size, backing store |
| `large_256mib` | many READ/WRITE PDUs, credits; reports MiB/s each way |
| `random_access_reads` | MiB-aligned ranges out of a 64 MiB file |
| `append_overwrite_truncate` | the same edits on a local file and the share's copy: append, write in the middle, shrink, grow, write past the end |
| `rename_file_dir_replace` | rename a file, a directory, onto an existing file, across directories |
| `case_only_rename` | `Foo.txt` -> `foo.txt` |
| `delete_semantics` | rmdir of a non-empty directory refused, of an empty one not; recursive delete; deleting what isn't there |
| `special_filenames` | spaces, punctuation, quotes, non-ASCII, emoji, a leading dot, 200+ characters; a different-case lookup |
| `deep_tree_long_names` | 22 nested directories (near Windows' 260-character path limit) |
| `many_small_files_1000` | CREATE/CLOSE churn, QUERY_DIRECTORY paging; timed |
| `big_folder_5000` | a 5000-entry folder enumerated bare, with attributes (Finder/Explorer), and 200 lookups by name; timed, with ceilings |
| `timestamps` | set a modification time through the share, read it back on both ends, and the other way |
| `disk_space` | the free space the client shows is the server volume's |
| `sparse_4_5gib` | a file extended past 32 bits, its last MiB written and read, a MiB out of the hole |
| `concurrent_writers_8`, `concurrent_readers_8` | eight processes at once on one client |
| `churn_while_listing` | 300 create/rename/delete cycles while another process lists without pause |
| `client_killed_mid_transfer` | a copy killed half-way; the server must carry on |
| `parallel_listings_50` | 50 listings at once |
| `second_share_isolation` | two shares of one server don't see each other |
| `vfs_share`, `vfs_readonly_share` | the BYO-VFS chain through the `localvfs` provider, writable and declared read-only |
| `wrong_credentials_refused` | wrong password, wrong user, no such share: refused, promptly |
| `linux_dialects_and_signing` | Linux only: vers=2.0/2.1/3.0/3.02 and the default negotiation, `sign` on 2.1 and 3.02; 3.1.1 and `seal` refused cleanly |
| `linux_smbclient` | Linux only: Samba's client puts, gets, renames, deletes |
| `linux_sessions_50` | Linux only: 50 SMB sessions at once |
| `server_survived_and_log_clean` | the server process is still up; no ERROR/panic in its log |
| `guest_roundtrip` | the `-guest` server, anonymously (skipped on Windows clients: Windows 11 refuses unsigned guest sessions) |
| `readonly_server` | the `-readonly` server refuses write, delete, mkdir, rename, truncate; reads work |

## TestMultiClient

Every other machine of the rig mounts one server at once (up to five clients, all three OSes).
Each writes a file and a directory; each must see every other's, byte for byte; each renames and
deletes its own, and the others must see that too. Checks poll for up to 45 s: Windows keeps
directory and file-information caches for 10 s.

## TestStress

One server, every other machine hammering it at once for `PSMB_STRESS_SECONDS` (default 120) with
the `psmbstress` worker: small-file churn, medium and large files with random-offset reads,
publish-by-rename, in-place overwrites, appends and truncates, directory trees with renames,
listing checks, a shared corpus, and cross-client reads of what the other clients published. All
content is a pure function of (seed, path, offset), so every byte any client reads is verified
without any state being shared, and a stale read is told apart from corruption. The Linux clients
mount with `vers=2.1` and `vers=3.02` so both signing algorithms (HMAC-SHA256, AES-CMAC) are under
load at once.

A leg fails on: a worker's failure or stall; reconnect or signing errors in the client OS logs
(`dmesg`, the Windows SmbClient event logs, `smbutil statshares` and the `smbfs` log on macOS);
ERROR/panic lines in the server log; the server dying or holding several times its resting memory
afterwards; and the audit of the backing store on the server host (every published file present
and byte-exact, nothing left over). The report goes to `portable-smb-server local\results\`.

    PSMB_STRESS_LEGS=windows,macos   only those server OSes
    PSMB_STRESS_WORKERS=8            worker goroutines per client (default 4)
    PSMB_STRESS_LARGE_MB=64          largest large file (default 32)
    PSMB_STRESS_SEED=42              reproduce a run

## How it drives the machines

`host.go` is one SSH connection per machine (`golang.org/x/crypto/ssh`, files over SFTP), running
commands written in the machine's own shell: bash, zsh/BSD userland, or PowerShell (the Windows
VMs' SSH default shell; the exit code and UTF-8 output are wrapped in). On Windows a `net use`
drive is only visible inside the logon session that mapped it, which is why a client's mount and
everything that uses it share one connection. `ops.go` is the one definition of copy, hash, list,
rename, truncate, write-at-offset and so on for the three OSes, so the conditions can't drift
apart; `client.go` the mounts; `server.go` the deploy/start/stop of the server under test (started
detached: `nohup` on Unix, `Win32_Process.Create` on Windows, the one way to outlive the SSH
session) and its providers.
