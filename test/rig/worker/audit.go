package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// The shared read-only corpus: files the harness seeds straight into the server's backing store
// before the clients mount, which every client reads throughout (and the audit re-verifies). Their
// content is a function of their path like everything else.
func corpusFiles() []pubFile {
	sizes := []int64{1 << 10, 7 << 10, 64 << 10, 300 << 10, 1 << 20, 3 << 20, 5 << 20, 8 << 20}
	var out []pubFile
	for i, s := range sizes {
		out = append(out, pubFile{rel: path.Join("corpus", fmt.Sprintf("c%d_%d.bin", i, s)), size: s})
	}
	return out
}

func cmdSeed(args []string) int {
	fl := flag.NewFlagSet("seed", flag.ExitOnError)
	dir := fl.String("dir", "", "the server's backing directory")
	seed := fl.Uint64("seed", 1, "run seed")
	_ = fl.Parse(args)
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "seed: -dir is required")
		return 2
	}
	if err := os.MkdirAll(filepath.Join(*dir, "corpus"), 0o777); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		return 1
	}
	for _, f := range corpusFiles() {
		if err := writeFile(filepath.Join(*dir, filepath.FromSlash(f.rel)), newContent(*seed, f.rel), f.size, 1<<20, false); err != nil {
			fmt.Fprintln(os.Stderr, "seed:", err)
			return 1
		}
	}
	fmt.Printf("seeded %d corpus files under %s\n", len(corpusFiles()), *dir)
	return 0
}

type auditResult struct {
	Verified   int      `json:"verified"`
	Bytes      int64    `json:"bytes"`
	Mismatches []string `json:"mismatches"`
	Missing    []string `json:"missing"`
	Strays     []string `json:"strays"`
}

// cmdAudit verifies the server's backing store on the server host itself: every file a client
// published (the manifest, gathered from the workers' results) is there with exactly the expected
// bytes, the corpus is intact, and nothing else is left under stress/.
func cmdAudit(args []string) int {
	fl := flag.NewFlagSet("audit", flag.ExitOnError)
	dir := fl.String("dir", "", "the server's backing directory")
	seed := fl.Uint64("seed", 1, "run seed")
	manifest := fl.String("manifest", "", "JSON list of {path, size} the clients published")
	_ = fl.Parse(args)
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "audit: -dir is required")
		return 2
	}
	var expected []expectedFile
	if *manifest != "" {
		data, err := os.ReadFile(*manifest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit:", err)
			return 1
		}
		if err := json.Unmarshal(data, &expected); err != nil {
			fmt.Fprintln(os.Stderr, "audit: manifest:", err)
			return 1
		}
	}
	res := auditResult{Mismatches: []string{}, Missing: []string{}, Strays: []string{}}
	want := map[string]int64{}
	for _, e := range expected {
		want[e.Path] = e.Size
	}
	for _, c := range corpusFiles() {
		want[c.rel] = c.size
	}
	for rel, size := range want {
		p := filepath.Join(*dir, filepath.FromSlash(rel))
		if _, err := os.Stat(p); err != nil {
			res.Missing = append(res.Missing, rel)
			continue
		}
		n, err := verifyFile(p, newContent(*seed, rel), size)
		res.Bytes += n
		if err != nil {
			res.Mismatches = append(res.Mismatches, err.Error())
			continue
		}
		res.Verified++
	}
	// Anything else under stress/ is a stray.
	stressDir := filepath.Join(*dir, "stress")
	_ = filepath.WalkDir(stressDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, *dir))
		rel = strings.TrimPrefix(rel, "/")
		if _, ok := want[rel]; !ok && !ignoredName(d.Name()) {
			res.Strays = append(res.Strays, rel)
		}
		return nil
	})
	sort.Strings(res.Missing)
	sort.Strings(res.Strays)
	js, _ := json.Marshal(res)
	fmt.Println(string(js))
	if len(res.Mismatches) > 0 || len(res.Missing) > 0 {
		return 1
	}
	return 0
}
