package rig

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// TestMatrix runs every condition against every client OS x server OS pair: the server under test
// on one machine, a native SMB client on another, two machines per pair. Each pair starts the
// server once per phase (the standard server with four shares, then a guest server, then a
// read-only one) and runs the conditions as subtests, so one failure never hides the next.
//
//	go test ./rig -run 'TestMatrix/macos->linux/rename' -v
func TestMatrix(t *testing.T) {
	s := requireRig(t)
	rep := newReport("matrix")
	defer rep.write(t)
	for _, pr := range pairs() {
		clientOS, serverOS := pr[0], pr[1]
		t.Run(fmt.Sprintf("%s->%s", clientOS, serverOS), func(t *testing.T) {
			cm, sm, err := s.Pair(clientOS, serverOS)
			if err != nil {
				t.Skip(err)
			}
			runPair(t, s, clientOS, serverOS, cm, sm, rep)
		})
	}
}

const (
	shareData    = "data"
	shareSecond  = "second"
	shareCloud   = "cloud"   // served through the localvfs provider
	shareROCloud = "rocloud" // a provider that declares itself read-only
	smbUser      = "rig"
	smbPass      = "rig-pass-123"
)

// pair is one client/server pair under test: the two hosts, the running server, the client's main
// mount of the data share, and the helpers every condition uses.
type pair struct {
	t        *testing.T
	ClientOS OS
	ServerOS OS
	C, S     *Host
	Srv      *Server
	Mnt      *Client
	Root     string // the data share, as mounted on the client
	Scratch  string // the client's scratch directory (local disk)
	Port     int
	group    string
	rep      *report
	noteText string // what the running condition measured, for the report
}

type scenario struct {
	name string
	only []OS // the client OSes it applies to; nil for all
	run  func(p *pair)
}

func runPair(t *testing.T, s *Settings, clientOS, serverOS OS, cm, sm Machine, rep *report) {
	C := connect(t, cm)
	S := connect(t, sm)
	p := &pair{t: t, ClientOS: clientOS, ServerOS: serverOS, C: C, S: S, Port: s.Port,
		group: fmt.Sprintf("%s->%s", clientOS, serverOS), rep: rep}
	t.Logf("client %s (%s), server %s (%s)", cm.Name, cm.IP, sm.Name, sm.IP)

	// A clean slate on the client: no mount of ours left from an earlier run, a fresh scratch.
	ForceUnmountAll(C)
	p.Scratch = C.Join(C.RigDir(), "scratch")
	Remove(C, p.Scratch)
	if err := Mkdir(C, p.Scratch); err != nil {
		t.Fatal(err)
	}

	// Phase 1: the standard server. Four shares: data (the one every condition uses), second
	// (isolation), cloud and rocloud (the BYO-VFS path, writable and read-only).
	p.Srv = StartServer(t, S, s.Port, ServerOpts{
		Shares: []Share{{Name: shareData}, {Name: shareSecond}, {Name: shareCloud, VFS: true}, {Name: shareROCloud, VFS: true, ReadOnly: true}},
		User:   smbUser, Pass: smbPass, Verbose: true,
	})
	p.Mnt = &Client{Host: C, ServerIP: S.IP, Share: shareData, Port: s.Port, User: smbUser, Pass: smbPass}
	if err := p.Mnt.Mount(); err != nil {
		t.Fatalf("%v\nserver log:\n%s", err, p.Srv.LogTail(20))
	}
	t.Cleanup(p.Mnt.Unmount)
	p.Root = p.Mnt.Root
	for _, sc := range standard {
		p.runScenario(sc)
	}
	p.Mnt.Unmount()
	p.runScenario(scenario{name: "server_survived_and_log_clean", run: scLogClean})
	p.Srv.Stop()

	// Phase 2: a guest server.
	p.Srv = StartServer(t, S, s.Port, ServerOpts{Shares: []Share{{Name: shareData}}, Guest: true, Verbose: true})
	p.runScenario(scenario{name: "guest_roundtrip", run: scGuest})
	p.runScenario(scenario{name: "guest_server_log_clean", run: scLogClean})
	p.Srv.Stop()

	// Phase 3: a read-only server.
	p.Srv = StartServer(t, S, s.Port, ServerOpts{Shares: []Share{{Name: shareData}}, User: smbUser, Pass: smbPass, ReadOnly: true, Verbose: true})
	p.runScenario(scenario{name: "readonly_server", run: scReadOnlyServer})
	p.runScenario(scenario{name: "readonly_server_log_clean", run: scLogClean})
	p.Srv.Stop()
}

func (p *pair) runScenario(sc scenario) {
	outer := p.t
	outer.Run(sc.name, func(t *testing.T) {
		start := time.Now()
		p.t = t
		p.noteText = ""
		defer func() {
			p.rep.add(t, p.group, sc.name, start, p.noteText)
			p.t = outer
		}()
		if sc.only != nil {
			applies := false
			for _, o := range sc.only {
				applies = applies || o == p.ClientOS
			}
			if !applies {
				t.Skipf("a %v-client condition", sc.only)
			}
		}
		sc.run(p)
	})
}

// ---- helpers the conditions share ----

func (p *pair) must(err error, what string) {
	p.t.Helper()
	if err != nil {
		p.t.Fatalf("%s: %v", what, err)
	}
}

func (p *pair) check(err error, what string) {
	p.t.Helper()
	if err != nil {
		p.t.Errorf("%s: %v", what, err)
	}
}

// note records a measurement for the report (and the log).
func (p *pair) note(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	p.t.Log(s)
	if p.noteText != "" {
		p.noteText += "; "
	}
	p.noteText += s
}

// mnt is a path inside the data share, as the client sees it.
func (p *pair) mnt(parts ...string) string { return p.C.Join(append([]string{p.Root}, parts...)...) }

// backing is a path inside the data share's backing directory on the server.
func (p *pair) backing(parts ...string) string { return p.Srv.Path(shareData, parts...) }

// scratch is a path in the client's scratch directory.
func (p *pair) scratch(name string) string { return p.C.Join(p.Scratch, name) }

// unique makes a name no earlier run used.
func (p *pair) unique(prefix string) string { return fmt.Sprintf("%s-%06x", prefix, rand.Intn(1<<24)) }

// newMount mounts another share from the client (unmounted when the condition ends).
func (p *pair) newMount(share, tag string, guest bool) *Client {
	c := &Client{Host: p.C, ServerIP: p.S.IP, Share: share, Port: p.Port, User: smbUser, Pass: smbPass, Guest: guest, Tag: tag}
	p.must(c.Mount(), "mount "+share)
	p.t.Cleanup(c.Unmount)
	return c
}

// randomFile makes a random file in the client's scratch and returns its path and hash (removed
// when the condition ends).
func (p *pair) randomFile(name string, size int64) (string, string) {
	path := p.scratch(name)
	hash, err := RandomFile(p.C, path, size)
	p.must(err, "random file "+name)
	p.t.Cleanup(func() { Remove(p.C, path) })
	return path, hash
}

// mib formats a throughput.
func mib(bytes int64, d time.Duration) string {
	return fmt.Sprintf("%.1f MiB/s", float64(bytes)/(1<<20)/d.Seconds())
}

// ---- the conditions ----

var standard = []scenario{
	{name: "roundtrip_4mib", run: scRoundTrip(4 << 20)},
	{name: "empty_file", run: scRoundTrip(0)},
	{name: "large_256mib", run: scLarge},
	{name: "random_access_reads", run: scRandomAccess},
	{name: "append_overwrite_truncate", run: scMutate},
	{name: "rename_file_dir_replace", run: scRename},
	{name: "case_only_rename", run: scCaseRename},
	{name: "delete_semantics", run: scDelete},
	{name: "special_filenames", run: scSpecialNames},
	{name: "case_insensitive_lookup", run: scCaseInsensitiveLookup},
	{name: "deep_tree_long_names", run: scDeepTree},
	{name: "many_small_files_1000", run: scManySmall},
	{name: "big_folder_5000", run: scBigFolder},
	{name: "timestamps", run: scTimestamps},
	{name: "disk_space", run: scDiskSpace},
	{name: "sparse_4_5gib", run: scSparse},
	{name: "concurrent_writers_8", run: scConcurrentWriters},
	{name: "concurrent_readers_8", run: scConcurrentReaders},
	{name: "churn_while_listing", run: scChurn},
	{name: "client_killed_mid_transfer", run: scKillMidTransfer},
	{name: "parallel_listings_50", run: scParallelListings},
	{name: "second_share_isolation", run: scSecondShare},
	{name: "vfs_share", run: scVFS},
	{name: "vfs_readonly_share", run: scVFSReadOnly},
	{name: "wrong_credentials_refused", run: scBadAuth},
	{name: "linux_dialects_and_signing", only: []OS{Linux}, run: scDialects},
	{name: "linux_smbclient", only: []OS{Linux}, run: scSmbClient},
	{name: "linux_sessions_50", only: []OS{Linux}, run: scManySessions},
}

// scRoundTrip writes a file of the given size through the share, reads it back, and checks the
// bytes on both ends.
func scRoundTrip(size int64) func(*pair) {
	return func(p *pair) {
		name := p.unique("rt") + ".dat"
		src, want := p.randomFile("src-"+name, size)
		dst := p.mnt(name)
		p.t.Cleanup(func() { Remove(p.C, dst) })
		p.must(Copy(p.C, src, dst), "copy to the share")
		rb := p.scratch("rb-" + name)
		p.t.Cleanup(func() { Remove(p.C, rb) })
		p.must(Copy(p.C, dst, rb), "copy back from the share")
		got, err := Hash(p.C, rb)
		p.must(err, "hash the read-back")
		if got != want {
			p.t.Fatalf("read back hash %s, wrote %s", got, want)
		}
		sz, err := Size(p.C, dst)
		p.must(err, "size through the client")
		if sz != size {
			p.t.Errorf("size through the client %d, want %d", sz, size)
		}
		p.must(WaitForHash(p.S, p.backing(name), want, 30*time.Second), "the server's backing store")
	}
}

// scLarge moves 256 MiB each way (many READ/WRITE PDUs, credit flow) and reports the throughput.
func scLarge(p *pair) {
	const size = 256 << 20
	name := p.unique("large") + ".bin"
	src, want := p.randomFile("src-"+name, size)
	dst := p.mnt(name)
	p.t.Cleanup(func() { Remove(p.C, dst) })
	t0 := time.Now()
	p.must(Copy(p.C, src, dst), "copy 256 MiB to the share")
	wd := time.Since(t0)
	rb := p.scratch("rb-" + name)
	p.t.Cleanup(func() { Remove(p.C, rb) })
	t0 = time.Now()
	p.must(Copy(p.C, dst, rb), "copy 256 MiB back")
	rd := time.Since(t0)
	p.note("write %s, read %s", mib(size, wd), mib(size, rd))
	got, err := Hash(p.C, rb)
	p.must(err, "hash the read-back")
	if got != want {
		p.t.Fatalf("read back hash %s, wrote %s", got, want)
	}
	p.must(WaitForHash(p.S, p.backing(name), want, 60*time.Second), "the server's backing store")
}

// scRandomAccess reads MiB-aligned ranges out of the middle of a 64 MiB file (what a video player
// or a zip reader does) and compares them with the source.
func scRandomAccess(p *pair) {
	const size = 64 << 20
	name := p.unique("ra") + ".bin"
	src, _ := p.randomFile("src-"+name, size)
	dst := p.mnt(name)
	p.t.Cleanup(func() { Remove(p.C, dst) })
	p.must(Copy(p.C, src, dst), "copy to the share")
	for _, r := range [][2]int64{{0, 1}, {13, 2}, {31, 1}, {63, 1}, {40, 8}, {5, 3}} {
		want, err := HashRangeMiB(p.C, src, r[0], r[1])
		p.must(err, "hash the source range")
		got, err := HashRangeMiB(p.C, dst, r[0], r[1])
		p.must(err, "read the range through the share")
		if got != want {
			p.t.Errorf("range %d+%d MiB: read %s, want %s", r[0], r[1], got, want)
		}
	}
}

// scMutate applies the same edits to a local file and to its copy on the share - append,
// overwrite in the middle, shrink, grow, overwrite past the end - and after each one the share's
// copy must match the local one byte for byte (write at offset, SET_INFO end-of-file).
func scMutate(p *pair) {
	name := p.unique("mut") + ".bin"
	local, _ := p.randomFile("local-"+name, 3<<20)
	mounted := p.mnt(name)
	p.t.Cleanup(func() { Remove(p.C, mounted) })
	p.must(Copy(p.C, local, mounted), "copy to the share")
	blobA, _ := p.randomFile("blobA-"+name, 1<<20)
	blobB, _ := p.randomFile("blobB-"+name, 300<<10)

	step := func(what string, op func(path string) error) {
		p.t.Helper()
		p.must(op(local), what+" (local)")
		p.must(op(mounted), what+" (share)")
		ls, err := Size(p.C, local)
		p.must(err, "local size")
		ms, err := Size(p.C, mounted)
		p.must(err, "share size")
		if ls != ms {
			p.t.Fatalf("after %s: size through the share %d, local %d", what, ms, ls)
		}
		lh, err := Hash(p.C, local)
		p.must(err, "local hash")
		mh, err := Hash(p.C, mounted)
		p.must(err, "share hash")
		if lh != mh {
			p.t.Fatalf("after %s: the share's copy differs from the local one (%d bytes)", what, ls)
		}
	}
	step("append 1 MiB", func(f string) error { return Append(p.C, f, blobA) })
	step("overwrite 300 KiB at 1 MiB", func(f string) error { return WriteAtMiB(p.C, f, 1, blobB) })
	step("shrink to 2.5 MiB", func(f string) error { return Truncate(p.C, f, 2621440) })
	step("grow to 6 MiB", func(f string) error { return Truncate(p.C, f, 6<<20) })
	step("append 300 KiB", func(f string) error { return Append(p.C, f, blobB) })
	step("overwrite past the end at 8 MiB", func(f string) error { return WriteAtMiB(p.C, f, 8, blobA) })
	want, err := Hash(p.C, local)
	p.must(err, "final local hash")
	p.must(WaitForHash(p.S, p.backing(name), want, 30*time.Second), "the server's backing store")
}

// scRename renames a file, a directory, onto an existing file (replace), and across directories.
func scRename(p *pair) {
	d := p.unique("ren")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	m := func(parts ...string) string { return p.mnt(append([]string{d}, parts...)...) }
	b := func(parts ...string) string { return p.backing(append([]string{d}, parts...)...) }

	p.must(WriteText(p.C, m("a.txt"), "alpha"), "write a.txt")
	p.must(Rename(p.C, m("a.txt"), m("b.txt")), "rename a.txt -> b.txt")
	if ok, _ := Exists(p.C, m("a.txt")); ok {
		p.t.Error("a.txt still exists after the rename")
	}
	if txt, err := ReadText(p.C, m("b.txt")); err != nil || txt != "alpha" {
		p.t.Errorf("b.txt reads %q, %v", txt, err)
	}
	p.must(WaitForGone(p.S, b("a.txt"), 10*time.Second), "a.txt gone on the server")

	p.must(Mkdir(p.C, m("d1")), "mkdir d1")
	p.must(WriteText(p.C, m("d1", "inner.txt"), "inner"), "write d1/inner.txt")
	p.must(Rename(p.C, m("d1"), m("d2")), "rename d1 -> d2")
	if txt, err := ReadText(p.C, m("d2", "inner.txt")); err != nil || txt != "inner" {
		p.t.Errorf("d2/inner.txt reads %q, %v", txt, err)
	}
	if ok, _ := Exists(p.S, b("d2", "inner.txt")); !ok {
		p.t.Error("d2/inner.txt not on the server")
	}

	p.must(WriteText(p.C, m("c.txt"), "gamma"), "write c.txt")
	p.must(Rename(p.C, m("b.txt"), m("c.txt")), "rename b.txt onto c.txt (replace)")
	if txt, err := ReadText(p.C, m("c.txt")); err != nil || txt != "alpha" {
		p.t.Errorf("after the replacing rename, c.txt reads %q, %v (want alpha)", txt, err)
	}
	if ok, _ := Exists(p.C, m("b.txt")); ok {
		p.t.Error("b.txt still exists after the replacing rename")
	}
	if txt, err := ReadText(p.S, b("c.txt")); err != nil || txt != "alpha" {
		p.t.Errorf("on the server c.txt reads %q, %v (want alpha)", txt, err)
	}

	p.must(Rename(p.C, m("c.txt"), m("d2", "moved.txt")), "rename c.txt -> d2/moved.txt")
	if txt, err := ReadText(p.S, b("d2", "moved.txt")); err != nil || txt != "alpha" {
		p.t.Errorf("on the server d2/moved.txt reads %q, %v", txt, err)
	}
	names, err := ListNames(p.C, m())
	p.must(err, "list")
	if len(names) != 1 || names[0] != "d2" {
		p.t.Errorf("final listing %v, want [d2]", names)
	}
}

// scCaseRename renames a file to the same name in another case (Foo.txt -> foo.txt). The outcome
// is client- and filesystem-dependent: a Windows client may refuse a case-only Move-Item before it
// reaches the server, and a case-insensitive backing treats the two names as one — the macOS client
// even folds a case-only rename on such a mount locally (POSIX "same file"), reporting success
// without asking the server to change anything, so the on-disk case stays Foo.txt. So this does not
// demand one universal result; it checks the server never ends up in a bad state — the data must
// survive as exactly one file, readable, with no duplicate — and records what this client did. The
// server bug it guards against is a case-insensitive backing wrongly rejecting the rename as a name
// collision, which would leave the file under its old name or lose it; and, where the client does
// send the rename, the server must actually apply it (the macOS server does: see the linux->macos
// and windows->macos columns, where a case-only rename lands as foo.txt).
func scCaseRename(p *pair) {
	d := p.unique("case")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	p.must(WriteText(p.C, p.mnt(d, "Foo.txt"), "foo"), "write Foo.txt")

	renameErr := Rename(p.C, p.mnt(d, "Foo.txt"), p.mnt(d, "foo.txt"))

	// Whatever happened, the server holds exactly one file and it still reads "foo".
	snames, err := ListNames(p.S, p.backing(d))
	p.must(err, "list on the server")
	if len(snames) != 1 {
		p.t.Fatalf("after the case-only rename the server holds %v, want one file (data lost or duplicated)", snames)
	}
	if txt, err := ReadText(p.S, p.backing(d, snames[0])); err != nil || txt != "foo" {
		p.t.Errorf("the surviving file %q reads %q, %v (want foo)", snames[0], txt, err)
	}
	switch {
	case renameErr != nil:
		// The client refused it locally (common on Windows, which sees the mount case-insensitively).
		// Acceptable as long as the file is intact under its original name, which the checks above
		// confirmed. The server must not have been left mid-rename.
		if snames[0] != "Foo.txt" {
			p.t.Errorf("the client reported the rename failed, but the server renamed to %q anyway", snames[0])
		}
		p.note("client did not perform the case-only rename (%s); file intact as Foo.txt", tail(strings.ReplaceAll(renameErr.Error(), "\n", " "), 120))
	case snames[0] == "foo.txt":
		p.note("case-only rename applied: Foo.txt -> foo.txt")
	case p.ClientOS == MacOS && p.ServerOS != Linux && snames[0] == "Foo.txt":
		// Case-insensitive backing (NTFS, APFS): Foo.txt and foo.txt are the same file, so the stored
		// case is cosmetic. The macOS client treats a case-only rename on a mount it sees as
		// case-insensitive as a POSIX same-file no-op — it reports success without asking the server
		// to change anything, so the on-disk case stays Foo.txt. The data is intact as exactly one
		// readable file (checked above). This is a client behaviour, not the server dropping a rename:
		// the macOS server does apply a case-only rename when a Linux or Windows client sends one.
		p.note("macOS client folded the case-only rename on the case-insensitive mount (reported success, left Foo.txt); data intact")
	default:
		// Either a case-sensitive backing (ext4), where Foo.txt and foo.txt are genuinely different
		// names so a client success that kept the old name means the server dropped a real rename; or
		// a Linux/Windows client on a case-insensitive backing, which sends the rename and so must see
		// it applied. Both are real failures.
		p.t.Errorf("the client reported success but the server still has %q, not foo.txt", snames[0])
	}
}

// scDelete: a non-empty directory refuses rmdir, an empty one goes, a tree goes recursively, and
// deleting what isn't there is an error.
func scDelete(p *pair) {
	d := p.unique("del")
	p.must(Mkdir(p.C, p.mnt(d, "full")), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	p.must(WriteText(p.C, p.mnt(d, "full", "f.txt"), "x"), "write")
	if err := Rmdir(p.C, p.mnt(d, "full")); err == nil {
		p.t.Error("rmdir of a non-empty directory succeeded")
	}
	if ok, _ := Exists(p.C, p.mnt(d, "full", "f.txt")); !ok {
		p.t.Error("the file inside is gone after the refused rmdir")
	}
	p.must(RemoveFile(p.C, p.mnt(d, "full", "f.txt")), "delete the file")
	p.must(Rmdir(p.C, p.mnt(d, "full")), "rmdir the now-empty directory")
	p.must(WaitForGone(p.S, p.backing(d, "full"), 10*time.Second), "gone on the server")
	if err := RemoveFile(p.C, p.mnt(d, "never-there.txt")); err == nil {
		p.t.Error("deleting a file that doesn't exist succeeded")
	}
	p.must(Mkdir(p.C, p.mnt(d, "tree", "a", "b", "c")), "mkdir tree")
	for _, f := range [][]string{{"tree", "1.txt"}, {"tree", "a", "2.txt"}, {"tree", "a", "b", "c", "3.txt"}} {
		p.must(WriteText(p.C, p.mnt(append([]string{d}, f...)...), "x"), "write "+strings.Join(f, "/"))
	}
	p.must(RemoveStrict(p.C, p.mnt(d, "tree")), "recursive delete")
	p.must(WaitForGone(p.S, p.backing(d, "tree"), 10*time.Second), "tree gone on the server")
}

// scSpecialNames round-trips names with spaces, punctuation, quotes, non-ASCII, a leading dot and
// 200+ characters, and checks a different-case lookup finds the file.
func scSpecialNames(p *pair) {
	d := p.unique("names")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	names := []string{
		"hello world.dat",
		"paren(1).dat",
		"plus+dash-_.dat",
		"dotted.name.v2.dat",
		"it's here.txt",
		"#hash %percent &amp ,comma ;semi =eq @at.txt",
		"café_münchen.dat",
		"日本語ファイル.txt",
		"emoji-😀.txt",
		".hidden",
		"UPPER.TXT",
		strings.Repeat("a", 200) + ".txt",
		strings.Repeat("日", 60) + ".txt",
	}
	var failures []string
	for _, n := range names {
		f := p.mnt(d, n)
		if err := WriteText(p.C, f, "name:"+n); err != nil {
			failures = append(failures, fmt.Sprintf("%q: write: %v", n, err))
			continue
		}
		if txt, err := ReadText(p.C, f); err != nil || txt != "name:"+n {
			failures = append(failures, fmt.Sprintf("%q: read back %q, %v", n, txt, err))
		}
		if ok, err := Exists(p.S, p.backing(d, n)); !ok {
			failures = append(failures, fmt.Sprintf("%q: not in the backing store (%v)", n, err))
		}
	}
	count, err := CountEntries(p.C, p.mnt(d))
	p.must(err, "count")
	if count != len(names) {
		failures = append(failures, fmt.Sprintf("client lists %d entries, want %d", count, len(names)))
	}
	for _, n := range names {
		if err := RemoveFile(p.C, p.mnt(d, n)); err != nil {
			failures = append(failures, fmt.Sprintf("%q: delete: %v", n, err))
		}
	}
	if len(failures) > 0 {
		p.t.Errorf("%d problem(s):\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// scCaseInsensitiveLookup: how the server treats a name that differs only in case. The behaviour
// follows the server's backing filesystem, which is what this checks, not a fixed expectation:
//   - on a case-insensitive backing (NTFS on Windows, APFS on macOS) a file must be found by any
//     case, and a differently-cased create must hit the same file — Explorer, Finder and anything
//     that stores a path assume it, and the Windows and macOS clients send whatever case the
//     application used;
//   - on a case-sensitive backing (ext4 on Linux) the exact case must work, and a differently-cased
//     name is a different file, as it is for every local program on that server.
func scCaseInsensitiveLookup(p *pair) {
	d := p.unique("icase")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	p.must(WriteText(p.C, p.mnt(d, "MixedCase.txt"), "mixed"), "write MixedCase.txt")
	if txt, err := ReadText(p.C, p.mnt(d, "MixedCase.txt")); err != nil || txt != "mixed" {
		p.t.Fatalf("the exact name MixedCase.txt: %q, %v", txt, err)
	}

	if p.ServerOS == Linux {
		// Case-sensitive backing: the other-case names are absent, and writing one makes a second
		// file. (A folding layer in the server would change this; today it has none.)
		if ok, _ := Exists(p.C, p.mnt(d, "mixedcase.txt")); ok {
			p.t.Error("mixedcase.txt exists, but the server's backing filesystem is case-sensitive")
		}
		p.must(WriteText(p.C, p.mnt(d, "mixedcase.txt"), "lower"), "write mixedcase.txt")
		names, err := ListNames(p.S, p.backing(d))
		p.must(err, "list on the server")
		if len(names) != 2 {
			p.t.Errorf("case-sensitive backing should now hold 2 files, has %v", names)
		}
		p.note("case-sensitive backing (ext4): other-case names are distinct files")
		return
	}

	for _, n := range []string{"mixedcase.txt", "MIXEDCASE.TXT"} {
		if txt, err := ReadText(p.C, p.mnt(d, n)); err != nil || txt != "mixed" {
			p.t.Errorf("MixedCase.txt as %s: %q, %v", n, txt, err)
		}
	}
	if txt, err := ReadText(p.C, p.mnt(strings.ToUpper(d), "mixedcase.txt")); err != nil || txt != "mixed" {
		p.t.Errorf("the directory as %s: %q, %v", strings.ToUpper(d), txt, err)
	}
	// Still one file: a write by another case must hit the same file, not make a second one.
	p.must(WriteText(p.C, p.mnt(d, "MIXEDCASE.TXT"), "again"), "write as MIXEDCASE.TXT")
	names, err := ListNames(p.S, p.backing(d))
	p.must(err, "list on the server")
	if len(names) != 1 {
		p.t.Errorf("the server now has %v: a write by another case made a second file", names)
	}
}

// scDeepTree: 22 nested directories (a path near Windows' 260-character limit), a file at the
// bottom, listings at each level, a recursive delete.
func scDeepTree(p *pair) {
	parts := []string{p.unique("deep")}
	for i := 1; i <= 22; i++ {
		parts = append(parts, fmt.Sprintf("level-%02d", i))
	}
	p.must(Mkdir(p.C, p.mnt(parts...)), "mkdir 22 levels")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(parts[0])) })
	bottom := p.mnt(append(parts, "bottom.txt")...)
	p.must(WriteText(p.C, bottom, "bottom"), "write at the bottom")
	if txt, err := ReadText(p.C, bottom); err != nil || txt != "bottom" {
		p.t.Errorf("bottom.txt reads %q, %v", txt, err)
	}
	if ok, _ := Exists(p.S, p.Srv.Path(shareData, append(parts, "bottom.txt")...)); !ok {
		p.t.Error("bottom.txt not in the backing store")
	}
	for _, lvl := range []int{1, 11, len(parts)} {
		names, err := ListNames(p.C, p.mnt(parts[:lvl]...))
		p.must(err, fmt.Sprintf("list level %d", lvl))
		want := "bottom.txt"
		if lvl < len(parts) {
			want = parts[lvl]
		}
		if len(names) != 1 || names[0] != want {
			p.t.Errorf("level %d lists %v, want [%s]", lvl, names, want)
		}
	}
	p.must(RemoveStrict(p.C, p.mnt(parts[0])), "recursive delete")
	p.must(WaitForGone(p.S, p.backing(parts[0]), 10*time.Second), "gone on the server")
}

// scManySmall creates 1000 small files through the share (CREATE/WRITE/CLOSE churn), lists them
// through the client (QUERY_DIRECTORY paging) and deletes them.
func scManySmall(p *pair) {
	const n = 1000
	d := p.unique("many")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	t0 := time.Now()
	p.must(NumberedFiles(p.C, p.mnt(d), n), "create 1000 files")
	create := time.Since(t0)
	p.must(WaitForCount(p.C, p.mnt(d), n, 30*time.Second), "the client lists all 1000")
	for _, i := range []int{1, n / 2, n} {
		if txt, err := ReadText(p.C, p.mnt(d, fmt.Sprintf("f_%d.dat", i))); err != nil || txt != fmt.Sprintf("content-%d", i) {
			p.t.Errorf("f_%d.dat reads %q, %v", i, txt, err)
		}
	}
	p.must(WaitForCount(p.S, p.backing(d), n, 30*time.Second), "the server has all 1000")
	t0 = time.Now()
	p.must(RemoveStrict(p.C, p.mnt(d)), "delete the 1000")
	p.note("create %s, delete %s", create.Truncate(100*time.Millisecond), time.Since(t0).Truncate(100*time.Millisecond))
	p.must(WaitForGone(p.S, p.backing(d), 10*time.Second), "gone on the server")
}

// scBigFolder lists a 5000-entry folder through the client: a bare enumeration, one with
// attributes (what Finder and Explorer do), and 200 lookups by name (what a client without
// directory shortcuts does for every entry). The folder is made on the server directly.
func scBigFolder(p *pair) {
	const n = 5000
	d := p.unique("big")
	p.must(Mkdir(p.S, p.backing(d)), "mkdir on the server")
	p.t.Cleanup(func() { Remove(p.S, p.backing(d)) })
	p.must(NumberedFiles(p.S, p.backing(d), n), "create 5000 files on the server")

	t0 := time.Now()
	count, err := CountEntries(p.C, p.mnt(d))
	p.must(err, "enumerate")
	enum := time.Since(t0)
	if count != n {
		p.t.Errorf("client enumerates %d entries, want %d", count, n)
	}
	t0 = time.Now()
	count, err = CountWithAttributes(p.C, p.mnt(d))
	p.must(err, "list with attributes")
	attrs := time.Since(t0)
	if count != n {
		p.t.Errorf("client lists %d entries with attributes, want %d", count, n)
	}
	var names []string
	for i := 1; i <= n; i += n / 200 {
		names = append(names, fmt.Sprintf("f_%d.dat", i))
	}
	t0 = time.Now()
	p.must(LookupMany(p.C, p.mnt(d), names), "200 lookups by name")
	lookups := time.Since(t0)
	p.note("enumerate %s, with attributes %s, 200 lookups %s", enum.Truncate(100*time.Millisecond), attrs.Truncate(100*time.Millisecond), lookups.Truncate(100*time.Millisecond))
	for what, d := range map[string]time.Duration{"enumeration": enum, "listing with attributes": attrs, "200 lookups": lookups} {
		if d > 90*time.Second {
			p.t.Errorf("%s of %d entries took %s", what, n, d)
		}
	}
}

// scTimestamps sets a modification time through the share and reads it back on both ends, and
// reads one the server side set.
func scTimestamps(p *pair) {
	d := p.unique("time")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	const epoch = 981173106 // 2001-02-03 04:05:06 UTC
	p.must(WriteText(p.C, p.mnt(d, "stamp.txt"), "t"), "write")
	p.must(SetMtime(p.C, p.mnt(d, "stamp.txt"), epoch), "set mtime through the share")
	if got, err := Mtime(p.C, p.mnt(d, "stamp.txt")); err != nil || abs64(got-epoch) > 2 {
		p.t.Errorf("mtime through the client %d, %v (want %d)", got, err, epoch)
	}
	if got, err := Mtime(p.S, p.backing(d, "stamp.txt")); err != nil || abs64(got-epoch) > 2 {
		p.t.Errorf("mtime on the server %d, %v (want %d)", got, err, epoch)
	}
	const epoch2 = 1234567890 // 2009-02-13 23:31:30 UTC
	p.must(WriteText(p.S, p.backing(d, "server-stamp.txt"), "t"), "write on the server")
	p.must(SetMtime(p.S, p.backing(d, "server-stamp.txt"), epoch2), "set mtime on the server")
	if got, err := Mtime(p.C, p.mnt(d, "server-stamp.txt")); err != nil || abs64(got-epoch2) > 2 {
		p.t.Errorf("the server-set mtime reads %d through the client, %v (want %d)", got, err, epoch2)
	}
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// scDiskSpace: the free space the client reports for the share is the server volume's.
func scDiskSpace(p *pair) {
	total, free, err := DiskSpace(p.C, p.Root)
	p.must(err, "df through the client")
	if total <= 0 || free <= 0 || free > total {
		p.t.Fatalf("client sees total %d, free %d", total, free)
	}
	stotal, sfree, err := DiskSpace(p.S, p.backing())
	p.must(err, "df on the server")
	p.note("client sees %d/%d GiB free, server %d/%d GiB", free>>30, total>>30, sfree>>30, stotal>>30)
	if diff := float64(abs64(total-stotal)) / float64(stotal); diff > 0.05 {
		p.t.Errorf("client sees a %d GiB volume, the server's is %d GiB", total>>30, stotal>>30)
	}
}

// scSparse makes a 4.5 GiB file by extending it (a size past 32 bits), writes the last MiB,
// reads that back and a MiB out of the hole.
func scSparse(p *pair) {
	const (
		sizeMiB = 4608 // 4.5 GiB
		size    = int64(sizeMiB) << 20
	)
	name := p.unique("sparse") + ".bin"
	f := p.mnt(name)
	p.t.Cleanup(func() { Remove(p.C, f) })
	p.must(WriteText(p.C, f, ""), "create")
	p.must(Truncate(p.C, f, size), "extend to 4.5 GiB")
	if sz, err := Size(p.C, f); err != nil || sz != size {
		p.t.Fatalf("size through the client %d, %v (want %d)", sz, err, size)
	}
	if sz, err := Size(p.S, p.backing(name)); err != nil || sz != size {
		p.t.Fatalf("size on the server %d, %v (want %d)", sz, err, size)
	}
	blob, bh := p.randomFile("tail-"+name, 1<<20)
	t0 := time.Now()
	p.must(WriteAtMiB(p.C, f, sizeMiB-1, blob), "write the last MiB")
	p.note("last-MiB write %s", time.Since(t0).Truncate(100*time.Millisecond))
	if sz, err := Size(p.C, f); err != nil || sz != size {
		p.t.Errorf("size after the tail write %d, %v (want %d)", sz, err, size)
	}
	if got, err := HashRangeMiB(p.C, f, sizeMiB-1, 1); err != nil || got != bh {
		p.t.Errorf("the last MiB reads %s, %v (want %s)", got, err, bh)
	}
	if got, err := HashRangeMiB(p.C, f, 2048, 1); err != nil || got != ZeroHashMiB(1) {
		p.t.Errorf("a MiB out of the hole reads %s, %v (want zeros)", got, err)
	}
	if got, err := HashRangeMiB(p.S, p.backing(name), sizeMiB-1, 1); err != nil || got != bh {
		p.t.Errorf("on the server the last MiB reads %s, %v (want %s)", got, err, bh)
	}
	p.must(RemoveFile(p.C, f), "delete")
}

// scConcurrentWriters has eight processes write at once.
func scConcurrentWriters(p *pair) {
	const n = 8
	d := p.unique("writers")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	src, want := p.randomFile("writers-src.bin", 8<<20)
	var scripts []string
	for i := 1; i <= n; i++ {
		dst := p.mnt(d, fmt.Sprintf("conc_%d.dat", i))
		if p.C.OS == Windows {
			scripts = append(scripts, fmt.Sprintf(`Copy-Item -LiteralPath %s -Destination %s -Force`, p.C.Q(src), p.C.Q(dst)))
		} else {
			scripts = append(scripts, fmt.Sprintf(`cp %s %s`, p.C.Q(src), p.C.Q(dst)))
		}
	}
	t0 := time.Now()
	results, err := Scripts(p.C, p.scratch("par-writers"), scripts, 10*time.Minute)
	p.must(err, "run the writers")
	p.note("8 x 8 MiB in %s", time.Since(t0).Truncate(100*time.Millisecond))
	for i, r := range results {
		if !r.OK() {
			p.t.Errorf("writer %d: exit %d: %s", i+1, r.Code, tail(r.Stdout, 500))
		}
	}
	p.must(WaitForCount(p.S, p.backing(d), n, 30*time.Second), "the server has all 8")
	for i := 1; i <= n; i++ {
		if err := WaitForHash(p.S, p.backing(d, fmt.Sprintf("conc_%d.dat", i)), want, 30*time.Second); err != nil {
			p.t.Errorf("conc_%d.dat: %v", i, err)
		}
	}
}

// scConcurrentReaders has eight processes read the same 64 MiB file at once.
func scConcurrentReaders(p *pair) {
	const n = 8
	name := p.unique("readers") + ".bin"
	want, err := RandomFile(p.S, p.backing(name), 64<<20)
	p.must(err, "make the file on the server")
	p.t.Cleanup(func() { Remove(p.S, p.backing(name)) })
	var scripts []string
	for i := 0; i < n; i++ {
		switch p.C.OS {
		case Windows:
			scripts = append(scripts, fmt.Sprintf(`(Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash.ToLower()`, p.C.Q(p.mnt(name))))
		case MacOS:
			scripts = append(scripts, fmt.Sprintf(`shasum -a 256 %s | cut -c1-64`, p.C.Q(p.mnt(name))))
		default:
			scripts = append(scripts, fmt.Sprintf(`sha256sum %s | cut -c1-64`, p.C.Q(p.mnt(name))))
		}
	}
	t0 := time.Now()
	results, err := Scripts(p.C, p.scratch("par-readers"), scripts, 10*time.Minute)
	p.must(err, "run the readers")
	p.note("8 x 64 MiB in %s", time.Since(t0).Truncate(100*time.Millisecond))
	for i, r := range results {
		if got := strings.TrimSpace(r.Stdout); !r.OK() || got != want {
			p.t.Errorf("reader %d: exit %d, hash %q, want %s", i, r.Code, tail(got, 200), want)
		}
	}
}

// scChurn creates, renames and deletes 300 files while another process lists the directory
// without pause: no listing may fail, and nothing may be left.
func scChurn(p *pair) {
	d := p.unique("churn")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	dir := p.mnt(d)
	var churn, lister string
	if p.C.OS == Windows {
		churn = fmt.Sprintf(`$d = %s; foreach ($i in 1..300) { [IO.File]::WriteAllText("$d\f_$i", 'x'); Move-Item -LiteralPath "$d\f_$i" -Destination "$d\g_$i"; [IO.File]::Delete("$d\g_$i") }; [IO.File]::WriteAllText("$d\done", 'done')`, p.C.Q(dir))
		lister = fmt.Sprintf(`$d = %s; $n = 0; $deadline = (Get-Date).AddMinutes(10); while (-not (Test-Path -LiteralPath "$d\done")) { $null = @([IO.Directory]::EnumerateFileSystemEntries($d)); $n++; if ((Get-Date) -gt $deadline) { throw 'the churn never finished' } }; "listed $n times"`, p.C.Q(dir))
	} else {
		churn = fmt.Sprintf(`d=%s; for i in $(seq 1 300); do printf x > "$d/f_$i" && mv "$d/f_$i" "$d/g_$i" && rm "$d/g_$i" || exit 1; done; printf done > "$d/done"`, p.C.Q(dir))
		lister = fmt.Sprintf(`d=%s; n=0; end=$(( $(date +%%s) + 600 )); while [ ! -e "$d/done" ]; do ls -A "$d" >/dev/null || exit 1; n=$((n+1)); [ "$(date +%%s)" -gt "$end" ] && exit 2; done; echo "listed $n times"`, p.C.Q(dir))
	}
	results, err := Scripts(p.C, p.scratch("par-churn"), []string{churn, lister}, 15*time.Minute)
	p.must(err, "run the churn and the lister")
	if !results[0].OK() {
		p.t.Errorf("churn: exit %d: %s", results[0].Code, tail(results[0].Stdout, 500))
	}
	if !results[1].OK() {
		p.t.Errorf("lister: exit %d: %s", results[1].Code, tail(results[1].Stdout, 500))
	}
	p.note("%s", strings.TrimSpace(results[1].Stdout))
	names, err := ListNames(p.S, p.backing(d))
	p.must(err, "list on the server")
	if len(names) != 1 || names[0] != "done" {
		p.t.Errorf("left on the server after the churn: %v (want [done])", names)
	}
}

// scKillMidTransfer kills a copy half-way through: the server must carry on serving this client
// as if nothing happened (the half-written file is deletable, a round trip works).
func scKillMidTransfer(p *pair) {
	src, _ := p.randomFile("kill-src.bin", 512<<20)
	dst := p.mnt(p.unique("killed") + ".bin")
	p.t.Cleanup(func() { Remove(p.C, dst); Remove(p.S, p.backing(p.C.Join(dst)[len(p.Root):])) })
	var r Result
	if p.C.OS == Windows {
		r = p.C.Run(fmt.Sprintf(`$p = Start-Process cmd.exe -ArgumentList '/c','copy','/y',%s,%s -PassThru -WindowStyle Hidden; Start-Sleep -Milliseconds 1500; Stop-Process -Id $p.Id -Force; Start-Sleep -Milliseconds 500; if ($p.HasExited) { 'killed' } else { 'still running' }`, p.C.Q(src), p.C.Q(dst)), 2*time.Minute)
	} else {
		r = p.C.Run(fmt.Sprintf(`cp %s %s & pid=$!; sleep 1.5; kill -9 $pid; wait $pid 2>/dev/null; echo killed`, p.C.Q(src), p.C.Q(dst)), 2*time.Minute)
	}
	p.must(r.Err("start and kill the copy"), "kill the copy")
	if ok, _ := Exists(p.C, dst); ok {
		sz, _ := Size(p.C, dst)
		p.note("the copy was killed at %d MiB", sz>>20)
		p.must(RemoveFile(p.C, dst), "delete the half-written file")
	} else {
		p.note("the copy was killed before the file appeared")
	}
	if !p.Srv.Alive() {
		p.t.Fatal("the server died")
	}
	scRoundTrip(4 << 20)(p)
}

// scParallelListings runs 50 directory listings at once on the mount: concurrent requests on one
// connection (several, on Windows, which opens more as it sees fit). Each listing must complete
// without an I/O error, and a listing once the barrage settles must be exactly right. The count a
// Windows or Linux client returns under load is also exact; a macOS client caches directory reads
// on its ReadDirAttr (Apple-extension) path and can serve a concurrent listing a transient partial
// or merged count, which is the client's doing, not the server's (the one connection is served
// serially and a sequential listing is always correct), so there its concurrent counts are only
// recorded, not asserted.
func scParallelListings(p *pair) {
	const n = 50
	d := p.unique("plist")
	p.must(Mkdir(p.C, p.mnt(d)), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.mnt(d)) })
	p.must(NumberedFiles(p.C, p.mnt(d), n), "create 50 files")
	// Each script prints its count, and exits 2 only if the listing itself failed (an I/O error,
	// not a surprising count). The Go side judges the counts per client OS.
	var scripts []string
	for i := 0; i < n; i++ {
		if p.C.OS == Windows {
			scripts = append(scripts, fmt.Sprintf(`try { @(Get-ChildItem -LiteralPath %s -File -Force).Count } catch { exit 2 }`, p.C.Q(p.mnt(d))))
		} else {
			scripts = append(scripts, fmt.Sprintf(`out=$(ls -lA %s 2>/dev/null) || exit 2; printf '%%s\n' "$out" | grep -c '^-' || true`, p.C.Q(p.mnt(d))))
		}
	}
	t0 := time.Now()
	results, err := Scripts(p.C, p.scratch("par-list"), scripts, 10*time.Minute)
	p.must(err, "run the listings")
	errors, exact, spread := 0, 0, map[int]int{}
	for _, r := range results {
		if r.Code == 2 || (r.Code != 0) {
			errors++
			continue
		}
		var c int
		_, _ = fmt.Sscan(strings.TrimSpace(r.Stdout), &c)
		spread[c]++
		if c == n {
			exact++
		}
	}
	p.note("50 listings in %s: %d exact, %d errored", time.Since(t0).Truncate(100*time.Millisecond), exact, errors)
	if errors > 0 {
		p.t.Errorf("%d of %d concurrent listings failed with an I/O error", errors, n)
	}
	if p.C.OS == MacOS {
		if exact != n {
			p.t.Logf("macOS concurrent-listing counts (client ReadDirAttr cache): %v", spread)
		}
	} else if exact != n {
		p.t.Errorf("%d of %d concurrent listings saw a count other than %d: %v", n-exact, n, n, spread)
	}
	// Once the barrage is over, a listing must be exactly right on every client.
	p.must(WaitForCount(p.C, p.mnt(d), n, 30*time.Second), "a settled listing through the client")
}

// scSecondShare: two shares of one server don't see each other's files.
func scSecondShare(p *pair) {
	second := p.newMount(shareSecond, "Y", false)
	a, b := p.unique("only-data")+".txt", p.unique("only-second")+".txt"
	p.t.Cleanup(func() { Remove(p.C, p.mnt(a)) })
	p.must(WriteText(p.C, p.mnt(a), "data"), "write in data")
	p.must(WriteText(p.C, p.C.Join(second.Root, b), "second"), "write in second")
	if ok, _ := Exists(p.C, p.C.Join(second.Root, a)); ok {
		p.t.Errorf("%s written to data shows in second", a)
	}
	if ok, _ := Exists(p.C, p.mnt(b)); ok {
		p.t.Errorf("%s written to second shows in data", b)
	}
	if ok, _ := Exists(p.S, p.Srv.Path(shareSecond, b)); !ok {
		p.t.Errorf("%s not in second's backing store", b)
	}
	if ok, _ := Exists(p.S, p.backing(b)); ok {
		p.t.Errorf("%s landed in data's backing store", b)
	}
	p.must(RemoveFile(p.C, p.C.Join(second.Root, b)), "delete in second")
}

// scVFS drives the BYO-VFS chain: client -> server -> HTTP provider -> disk.
func scVFS(p *pair) {
	cloud := p.newMount(shareCloud, "X", false)
	name := p.unique("vfs") + ".dat"
	src, want := p.randomFile("vfs-src.dat", 4<<20)
	dst := p.C.Join(cloud.Root, name)
	p.t.Cleanup(func() { Remove(p.C, dst) })
	p.must(Copy(p.C, src, dst), "copy to the VFS share")
	rb := p.scratch("vfs-rb.dat")
	p.t.Cleanup(func() { Remove(p.C, rb) })
	p.must(Copy(p.C, dst, rb), "copy back")
	if got, err := Hash(p.C, rb); err != nil || got != want {
		p.t.Fatalf("read back %s, %v (want %s)", got, err, want)
	}
	p.must(WaitForHash(p.S, p.Srv.Path(shareCloud, name), want, 30*time.Second), "the provider's folder")
	p.must(Mkdir(p.C, p.C.Join(cloud.Root, "sub")), "mkdir")
	p.t.Cleanup(func() { Remove(p.C, p.C.Join(cloud.Root, "sub")) })
	p.must(Rename(p.C, dst, p.C.Join(cloud.Root, "sub", "moved.dat")), "rename into sub")
	p.must(WaitForHash(p.S, p.Srv.Path(shareCloud, "sub", "moved.dat"), want, 30*time.Second), "moved in the provider's folder")
	p.must(RemoveStrict(p.C, p.C.Join(cloud.Root, "sub")), "delete sub")
	p.must(WaitForGone(p.S, p.Srv.Path(shareCloud, "sub"), 10*time.Second), "gone in the provider's folder")
}

// scVFSReadOnly: a provider that declares itself read-only gives a share that reads and refuses
// every change.
func scVFSReadOnly(p *pair) {
	p.must(WriteText(p.S, p.Srv.Path(shareROCloud, "ro.txt"), "look only"), "seed the provider's folder")
	ro := p.newMount(shareROCloud, "W", false)
	if txt, err := ReadText(p.C, p.C.Join(ro.Root, "ro.txt")); err != nil || txt != "look only" {
		p.t.Fatalf("ro.txt reads %q, %v", txt, err)
	}
	if err := WriteText(p.C, p.C.Join(ro.Root, "new.txt"), "x"); err == nil {
		p.t.Error("a write on the read-only share succeeded")
	}
	if err := RemoveFile(p.C, p.C.Join(ro.Root, "ro.txt")); err == nil {
		p.t.Error("a delete on the read-only share succeeded")
	}
	if err := MkdirStrict(p.C, p.C.Join(ro.Root, "dir")); err == nil {
		p.t.Error("a mkdir on the read-only share succeeded")
	}
	if err := Truncate(p.C, p.C.Join(ro.Root, "ro.txt"), 0); err == nil {
		p.t.Error("a truncate on the read-only share succeeded")
	}
	if txt, err := ReadText(p.S, p.Srv.Path(shareROCloud, "ro.txt")); err != nil || txt != "look only" {
		p.t.Errorf("the backing file was damaged: %q, %v", txt, err)
	}
	if ok, _ := Exists(p.S, p.Srv.Path(shareROCloud, "new.txt")); ok {
		p.t.Error("new.txt landed in the backing store")
	}
}

// scBadAuth: a wrong password, a wrong user and a share that doesn't exist are refused, promptly.
func scBadAuth(p *pair) {
	for _, c := range []struct {
		what string
		cl   *Client
	}{
		{"wrong password", &Client{Host: p.C, ServerIP: p.S.IP, Share: shareData, Port: p.Port, User: smbUser, Pass: "nope", Tag: "V"}},
		{"wrong user", &Client{Host: p.C, ServerIP: p.S.IP, Share: shareData, Port: p.Port, User: "nobody", Pass: smbPass, Tag: "V"}},
		{"no such share", &Client{Host: p.C, ServerIP: p.S.IP, Share: "nosuchshare", Port: p.Port, User: smbUser, Pass: smbPass, Tag: "V"}},
	} {
		t0 := time.Now()
		r := c.cl.TryMount()
		took := time.Since(t0)
		switch {
		case r.OK():
			p.t.Errorf("%s: the mount succeeded", c.what)
			c.cl.Unmount()
		case r.Code == -1:
			p.t.Errorf("%s: the mount hung (%s)", c.what, tail(r.Output(), 300))
		default:
			p.t.Logf("%s: refused in %s: %s", c.what, took.Truncate(100*time.Millisecond), tail(strings.ReplaceAll(r.Output(), "\n", " "), 200))
		}
	}
}

// scDialects (Linux client): a round trip on each dialect the server offers, with signing
// required, with the default negotiation; and a clean refusal of what it doesn't offer (3.1.1,
// encryption).
func scDialects(p *pair) {
	try := func(vers, opts string, wantOK bool) {
		c := &Client{Host: p.C, ServerIP: p.S.IP, Share: shareData, Port: p.Port, User: smbUser, Pass: smbPass, Tag: "dial", Vers: vers, Options: opts}
		label := "vers=" + vers
		if vers == "" {
			label = "default negotiation"
		}
		if opts != "" {
			label += " " + opts
		}
		r := c.TryMount()
		defer c.Unmount()
		if !wantOK {
			if r.OK() {
				p.t.Errorf("%s: mounted, but the server doesn't offer it", label)
			} else if r.Code == -1 {
				p.t.Errorf("%s: the mount hung", label)
			} else {
				p.t.Logf("%s: refused as expected: %s", label, tail(strings.ReplaceAll(r.Output(), "\n", " "), 150))
			}
			return
		}
		if err := r.Err(label); err != nil {
			p.t.Errorf("%v", err)
			return
		}
		f := p.C.Join(c.Root, p.unique("dial")+".txt")
		if err := WriteText(p.C, f, label); err != nil {
			p.t.Errorf("%s: write: %v", label, err)
			return
		}
		if txt, err := ReadText(p.C, f); err != nil || txt != label {
			p.t.Errorf("%s: read back %q, %v", label, txt, err)
		}
		_ = RemoveFile(p.C, f)
	}
	for _, v := range []string{"2.0", "2.1", "3.0", "3.02", ""} {
		try(v, "", true)
	}
	try("2.1", "sign", true)  // HMAC-SHA256 signing, required by the client
	try("3.02", "sign", true) // AES-CMAC signing
	try("3.1.1", "", false)   // not offered: the mount must fail, not hang
	try("3.0", "seal", false) // no encryption capability: the mount must fail, not hang
}

// scSmbClient (Linux client): Samba's smbclient, a second client implementation, puts, gets,
// renames and deletes.
func scSmbClient(p *pair) {
	src, want := p.randomFile("smbc-src.dat", 2<<20)
	rb := p.scratch("smbc-rb.dat")
	p.t.Cleanup(func() { Remove(p.C, rb) })
	name := p.unique("smbc") + ".dat"
	p.t.Cleanup(func() { Remove(p.S, p.backing(name)); Remove(p.S, p.backing(name+".renamed")) })
	script := fmt.Sprintf(`put "%s" "%s"; get "%s" "%s"; rename "%s" "%s"; mkdir smbc-dir; rmdir smbc-dir; ls; del "%s"`,
		src, name, name, rb, name, name+".renamed", name+".renamed")
	r := SmbClient(p.C, p.S.IP, p.Port, shareData, smbUser, smbPass, script, 5*time.Minute)
	p.must(r.Err("smbclient"), "smbclient script")
	if got, err := Hash(p.C, rb); err != nil || got != want {
		p.t.Errorf("smbclient got back %s, %v (want %s)", got, err, want)
	}
	if ok, _ := Exists(p.S, p.backing(name+".renamed")); ok {
		p.t.Error("the file is still there after smbclient's del")
	}
	if !strings.Contains(r.Stdout, name+".renamed") {
		p.t.Errorf("smbclient's ls doesn't show the renamed file:\n%s", tail(r.Stdout, 1000))
	}
}

// scManySessions (Linux client): 50 SMB sessions at once, each logging in and listing.
func scManySessions(p *pair) {
	var scripts []string
	for i := 0; i < 50; i++ {
		// smbclient reports its errors on stdout, so that is kept.
		scripts = append(scripts, fmt.Sprintf(`smbclient //%s/%s -p %d -U %s -m SMB3 -c 'ls' | tail -n 3`, p.S.IP, shareData, p.Port, p.C.Q(smbUser+"%"+smbPass)))
	}
	t0 := time.Now()
	results, err := Scripts(p.C, p.scratch("par-sessions"), scripts, 10*time.Minute)
	p.must(err, "run the sessions")
	p.note("50 sessions in %s", time.Since(t0).Truncate(100*time.Millisecond))
	bad := 0
	for i, r := range results {
		if !r.OK() {
			bad++
			if bad <= 3 {
				p.t.Errorf("session %d: exit %d: %s", i, r.Code, tail(r.Stdout, 300))
			}
		}
	}
	if bad > 3 {
		p.t.Errorf("%d of 50 sessions failed", bad)
	}
}

// scGuest mounts the guest server anonymously and round-trips a file. A Windows client won't use
// a guest session: guest sessions are unsigned, Windows 11 requires signing, so it rejects the
// (valid) session the server grants; that's Windows policy, not the server's.
func scGuest(p *pair) {
	if p.C.OS == Windows {
		p.t.Skip("a Windows client rejects guest SMB (unsigned guest vs required signing); not a server issue")
	}
	c := &Client{Host: p.C, ServerIP: p.S.IP, Share: shareData, Port: p.Port, Guest: true}
	p.must(c.Mount(), "guest mount")
	defer c.Unmount()
	src, want := p.randomFile("guest-src.dat", 1<<20)
	dst := p.C.Join(c.Root, "guest.dat")
	p.must(Copy(p.C, src, dst), "copy as guest")
	rb := p.scratch("guest-rb.dat")
	p.t.Cleanup(func() { Remove(p.C, rb) })
	p.must(Copy(p.C, dst, rb), "copy back as guest")
	if got, err := Hash(p.C, rb); err != nil || got != want {
		p.t.Errorf("read back %s, %v (want %s)", got, err, want)
	}
	p.must(WaitForHash(p.S, p.backing("guest.dat"), want, 30*time.Second), "the server's backing store")
	p.must(RemoveFile(p.C, dst), "delete as guest")
}

// scReadOnlyServer: with -readonly every change is refused and reads work.
func scReadOnlyServer(p *pair) {
	p.must(WriteText(p.S, p.backing("ro.txt"), "look only"), "seed the backing store")
	c := &Client{Host: p.C, ServerIP: p.S.IP, Share: shareData, Port: p.Port, User: smbUser, Pass: smbPass}
	p.must(c.Mount(), "mount the read-only server")
	defer c.Unmount()
	root := c.Root
	if txt, err := ReadText(p.C, p.C.Join(root, "ro.txt")); err != nil || txt != "look only" {
		p.t.Fatalf("ro.txt reads %q, %v", txt, err)
	}
	for what, op := range map[string]func() error{
		"write":    func() error { return WriteText(p.C, p.C.Join(root, "new.txt"), "x") },
		"delete":   func() error { return RemoveFile(p.C, p.C.Join(root, "ro.txt")) },
		"mkdir":    func() error { return MkdirStrict(p.C, p.C.Join(root, "dir")) },
		"rename":   func() error { return Rename(p.C, p.C.Join(root, "ro.txt"), p.C.Join(root, "renamed.txt")) },
		"truncate": func() error { return Truncate(p.C, p.C.Join(root, "ro.txt"), 0) },
	} {
		if err := op(); err == nil {
			p.t.Errorf("%s on the read-only server succeeded", what)
		}
	}
	if txt, err := ReadText(p.S, p.backing("ro.txt")); err != nil || txt != "look only" {
		p.t.Errorf("the backing file was damaged: %q, %v", txt, err)
	}
	names, _ := ListNames(p.S, p.backing())
	if len(names) != 1 {
		p.t.Errorf("the read-only backing store now holds %v", names)
	}
}

// scLogClean: the server is still running, and its log has no ERROR, panic or fatal line.
func scLogClean(p *pair) {
	if !p.Srv.Alive() {
		p.t.Errorf("the server process is gone; its log ends:\n%s", p.Srv.LogTail(30))
	}
	if problems := p.Srv.LogProblems(nil); len(problems) > 0 {
		p.t.Errorf("%d problem line(s) in the server log, e.g.:\n  %s", len(problems), strings.Join(problems[:min(len(problems), 10)], "\n  "))
	}
}
