package rig

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestMultiClient has every other machine of the rig mount one server at once - a Windows, a
// Linux and a macOS client, two of each where the server's OS allows - and checks that what one
// client writes, renames and deletes, every other client sees (through its own caches: Windows
// keeps directory and file-info caches for 10 s, so each check polls).
func TestMultiClient(t *testing.T) {
	s := requireRig(t)
	rep := newReport("multiclient")
	defer rep.write(t)
	for _, serverOS := range AllOS {
		t.Run(string(serverOS)+"-server", func(t *testing.T) {
			servers := s.Of(serverOS)
			if len(servers) < 2 {
				t.Skipf("the rig has fewer than two %s machines", serverOS)
			}
			sm := servers[1]
			S := connect(t, sm)
			start := time.Now()
			defer func() { rep.add(t, string(serverOS)+"-server", "cross_client_visibility", start, "") }()

			type client struct {
				h    *Host
				c    *Client
				tag  string
				hash string
			}
			var clients []*client
			for _, m := range s.Machines {
				if m.Name == sm.Name {
					continue
				}
				h, err := Connect(m)
				if err != nil {
					t.Logf("without %s: %v", m.Name, err)
					continue
				}
				t.Cleanup(h.Close)
				// Every client writes its source files in <RigDir>/scratch. The matrix creates that
				// directory on the machines it uses as clients; the ones it only ever uses as servers
				// (the second of each OS) reach it for the first time here, so make it now.
				if err := Mkdir(h, h.Join(h.RigDir(), "scratch")); err != nil {
					t.Logf("without %s: creating its scratch directory: %v", m.Name, err)
					continue
				}
				clients = append(clients, &client{h: h, tag: m.Name})
			}
			if len(clients) < 2 {
				t.Skipf("only %d client machine(s) reachable", len(clients))
			}
			srv := StartServer(t, S, s.Port, ServerOpts{Shares: []Share{{Name: shareData}}, User: smbUser, Pass: smbPass, Verbose: true})

			// each runs f for every client at once and reports each failure against its client.
			each := func(what string, f func(c *client) error) {
				t.Helper()
				var wg sync.WaitGroup
				errs := make([]error, len(clients))
				for i, c := range clients {
					wg.Add(1)
					go func(i int, c *client) {
						defer wg.Done()
						errs[i] = f(c)
					}(i, c)
				}
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Errorf("%s: %s: %v", clients[i].tag, what, err)
					}
				}
			}

			each("mount", func(c *client) error {
				ForceUnmountAll(c.h)
				c.c = &Client{Host: c.h, ServerIP: S.IP, Share: shareData, Port: s.Port, User: smbUser, Pass: smbPass}
				return c.c.Mount()
			})
			var mounted []*client
			for _, c := range clients {
				if c.c.Root != "" {
					mounted = append(mounted, c)
					t.Cleanup(c.c.Unmount)
				}
			}
			clients = mounted
			if len(clients) < 2 {
				t.Fatalf("only %d client(s) mounted", len(clients))
			}
			t.Logf("%d clients mounted the %s server", len(clients), sm.Name)

			// Every client writes a file and a directory with a file in it.
			each("write", func(c *client) error {
				src := c.h.Join(c.h.RigDir(), "scratch", "mc-"+c.tag+".dat")
				hash, err := RandomFile(c.h, src, 2<<20)
				if err != nil {
					return err
				}
				c.hash = hash
				if err := Copy(c.h, src, c.h.Join(c.c.Root, "from-"+c.tag+".dat")); err != nil {
					return err
				}
				if err := Mkdir(c.h, c.h.Join(c.c.Root, "dir-"+c.tag)); err != nil {
					return err
				}
				return WriteText(c.h, c.h.Join(c.c.Root, "dir-"+c.tag, "hello.txt"), "from "+c.tag)
			})

			// Every client sees every other client's file and directory, byte for byte.
			each("see the others' writes", func(c *client) error {
				for _, o := range clients {
					if o == c {
						continue
					}
					if err := WaitForHash(c.h, c.h.Join(c.c.Root, "from-"+o.tag+".dat"), o.hash, 45*time.Second); err != nil {
						return fmt.Errorf("%s's file: %v", o.tag, err)
					}
					if txt, err := ReadText(c.h, c.h.Join(c.c.Root, "dir-"+o.tag, "hello.txt")); err != nil || txt != "from "+o.tag {
						return fmt.Errorf("%s's dir-/hello.txt reads %q, %v", o.tag, txt, err)
					}
				}
				return nil
			})

			// Every client renames its file; every other client sees the new name and not the old.
			each("rename", func(c *client) error {
				return Rename(c.h, c.h.Join(c.c.Root, "from-"+c.tag+".dat"), c.h.Join(c.c.Root, "moved-"+c.tag+".dat"))
			})
			each("see the others' renames", func(c *client) error {
				for _, o := range clients {
					if o == c {
						continue
					}
					if err := WaitForGone(c.h, c.h.Join(c.c.Root, "from-"+o.tag+".dat"), 45*time.Second); err != nil {
						return fmt.Errorf("%s's old name: %v", o.tag, err)
					}
					if err := WaitForHash(c.h, c.h.Join(c.c.Root, "moved-"+o.tag+".dat"), o.hash, 45*time.Second); err != nil {
						return fmt.Errorf("%s's new name: %v", o.tag, err)
					}
				}
				return nil
			})

			// Every client appends to another's file in turn? No: concurrent writers to one file
			// are an application-level protocol. Every client deletes its own; the others see it go.
			each("delete", func(c *client) error {
				if err := RemoveFile(c.h, c.h.Join(c.c.Root, "moved-"+c.tag+".dat")); err != nil {
					return err
				}
				return RemoveStrict(c.h, c.h.Join(c.c.Root, "dir-"+c.tag))
			})
			each("see the others' deletes", func(c *client) error {
				for _, o := range clients {
					if o == c {
						continue
					}
					if err := WaitForGone(c.h, c.h.Join(c.c.Root, "moved-"+o.tag+".dat"), 45*time.Second); err != nil {
						return fmt.Errorf("%s's file: %v", o.tag, err)
					}
					if err := WaitForGone(c.h, c.h.Join(c.c.Root, "dir-"+o.tag), 45*time.Second); err != nil {
						return fmt.Errorf("%s's directory: %v", o.tag, err)
					}
				}
				return nil
			})

			names, err := ListNames(S, srv.Path(shareData))
			if err != nil {
				t.Error(err)
			} else if len(names) != 0 {
				t.Errorf("left in the backing store: %v", names)
			}
			each("unmount", func(c *client) error { c.c.Unmount(); return nil })
			if !srv.Alive() {
				t.Errorf("the server died; its log ends:\n%s", srv.LogTail(30))
			}
			if problems := srv.LogProblems(nil); len(problems) > 0 {
				t.Errorf("%d problem line(s) in the server log, e.g. %s", len(problems), problems[0])
			}
		})
	}
}
