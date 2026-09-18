// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build scripts

// Package scripts drives build.sh and build.ps1 against a copy of the module.
//
// The release is built by these scripts, so what they do with the build number,
// a failed compile, a failed package and a missing nfpm decides what ships. They
// are tested the way the binary is: by running them. Each test takes a fresh
// copy of the tree, so the version files in the repository are never touched.
package scripts

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// binary is the name the scripts give what they build.
const binary = "spk"

// A pcap-capable build carries a "p" after the version. Windows is always
// pcap-capable -- the capture path there is pure Go -- so a windows build's
// name is the same whatever the host. On linux it depends on which C toolchain
// the host has, so the linux cases below pass -nopcap and take the plain name.
const pcapSuffix = "p"

// root is the module directory the copies are taken from.
var root string

// fakeNfpm is a stand-in for nfpm built once for the run: it creates the
// --target file and exits with FAKE_NFPM_EXIT, so packaging can be made to
// succeed or fail without the real tool. Empty when it could not be built.
var fakeNfpm string

func TestMain(m *testing.M) {
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		panic(err)
	}
	root = abs

	tmp, err := os.MkdirTemp("", "spk-scripts")
	if err != nil {
		panic(err)
	}
	fakeNfpm = buildFakeNfpm(tmp)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

const fakeNfpmSource = `package main

import (
	"os"
	"strconv"
)

func main() {
	if code, err := strconv.Atoi(os.Getenv("FAKE_NFPM_EXIT")); err == nil && code != 0 {
		os.Exit(code)
	}
	for i, a := range os.Args {
		if a == "--target" && i+1 < len(os.Args) {
			os.WriteFile(os.Args[i+1], []byte("fake package\n"), 0o644)
		}
	}
}
`

func buildFakeNfpm(tmp string) string {
	src := filepath.Join(tmp, "fakenfpm")
	if err := os.MkdirAll(src, 0o700); err != nil {
		return ""
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(fakeNfpmSource), 0o600); err != nil {
		return ""
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fakenfpm\n\ngo 1.22\n"), 0o600); err != nil {
		return ""
	}
	bin := filepath.Join(tmp, "fakebin", "nfpm")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		return ""
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "fake nfpm did not build: %v\n%s", err, out)
		return ""
	}
	return bin
}

// copyTree copies what a build needs into a fresh directory: the module files,
// the scripts, the sources and the version files. Nothing else is read.
func copyTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum", "main.go", "build.sh", "build.ps1", "build.cmd"} {
		copyFile(t, filepath.Join(root, name), filepath.Join(dir, name))
	}
	for _, sub := range []string{"internal", "version"} {
		src := filepath.Join(root, sub)
		err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(src, path)
			dst := filepath.Join(dir, sub, rel)
			if d.IsDir() {
				return os.MkdirAll(dst, 0o700)
			}
			copyFile(t, path, dst)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// setBuildNumber writes the copy's build_number.txt.
func setBuildNumber(t *testing.T, dir, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "version", "build_number.txt"), []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildNumber reads the copy's build_number.txt, whatever line ending the
// script wrote it with.
func buildNumber(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "version", "build_number.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// script is one of the two build scripts and how to start it.
type script struct {
	name string
	cmd  func(dir string, args ...string) *exec.Cmd
}

// available lists the scripts this host can run: build.sh needs bash, build.ps1
// needs PowerShell. Both are present on every CI runner; a developer machine
// may have one.
func available(t *testing.T) []script {
	t.Helper()
	var out []script
	if bash, err := exec.LookPath("bash"); err == nil {
		out = append(out, script{"build.sh", func(dir string, args ...string) *exec.Cmd {
			return exec.Command(bash, append([]string{filepath.Join(dir, "build.sh")}, args...)...)
		}})
	}
	for _, name := range []string{"pwsh", "powershell"} {
		ps, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out = append(out, script{"build.ps1", func(dir string, args ...string) *exec.Cmd {
			return exec.Command(ps, append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass",
				"-File", filepath.Join(dir, "build.ps1")}, args...)...)
		}})
		break
	}
	if len(out) == 0 {
		t.Skip("neither bash nor PowerShell is available")
	}
	return out
}

// dropped are the variables a test must control rather than inherit.
var dropped = map[string]bool{
	"BUILD_NUMBER": true, "VERSION": true, "GOFLAGS": true, "GOBIN": true,
	"GOPROXY": true, "FAKE_NFPM_EXIT": true, "TMPDIR": true, "TMP": true, "TEMP": true,
}

// environ is the process environment with the controlled variables removed and
// the given ones set.
func environ(set map[string]string) []string {
	var out []string
	for _, kv := range os.Environ() {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if dropped[strings.ToUpper(key)] {
			continue
		}
		if _, ok := set[key]; ok {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range set {
		out = append(out, k+"="+v)
	}
	return out
}

// run starts the script in dir with the given environment on top of the
// process's own, and returns everything it printed.
func (s script) run(t *testing.T, dir string, env map[string]string, args ...string) (string, error) {
	t.Helper()
	cmd := s.cmd(dir, args...)
	cmd.Dir = dir
	cmd.Env = environ(env)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// pathWith returns PATH with dir in front, so a stand-in there wins.
func pathWith(dir string) string {
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// restrictedPath is a PATH holding the shells and go but not nfpm, so the
// script's other ways of finding nfpm can be seen to work. It reports false
// when nfpm still resolves on it, which means the host cannot host that test.
func restrictedPath(t *testing.T) (string, bool) {
	t.Helper()
	var dirs []string
	for _, tool := range []string{"go", "bash", "pwsh", "powershell"} {
		if p, err := exec.LookPath(tool); err == nil {
			dirs = append(dirs, filepath.Dir(p))
		}
	}
	if runtime.GOOS == "windows" {
		// The coreutils build.sh uses live beside Git's bash, one or two
		// directories up from wherever bash itself was found.
		if bash, err := exec.LookPath("bash"); err == nil {
			for _, up := range []string{"..", filepath.Join("..", "..")} {
				gitRoot := filepath.Join(filepath.Dir(bash), up)
				dirs = append(dirs, filepath.Join(gitRoot, "usr", "bin"), filepath.Join(gitRoot, "mingw64", "bin"))
			}
		}
		dirs = append(dirs, filepath.Join(os.Getenv("SystemRoot"), "System32"), os.Getenv("SystemRoot"))
	} else {
		dirs = append(dirs, "/usr/bin", "/bin")
	}
	path := strings.Join(dirs, string(os.PathListSeparator))

	t.Setenv("PATH", path)
	_, err := exec.LookPath("nfpm")
	return path, err != nil
}

// The build number in the file is the one this build takes, and the file is
// left holding the next: the convention every script and the release share.
func TestBuildNumberIsUsedThenBumped(t *testing.T) {
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			out, err := s.run(t, dir, map[string]string{"VERSION": "1.2.3"}, "-windows", "-amd64")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			bin := filepath.Join(dir, "build", "windows", binary+"_1.2.3.5"+pcapSuffix+"-windows-amd64.exe")
			if _, err := os.Stat(bin); err != nil {
				t.Errorf("binary not written as named: %v\n%s", err, out)
			}
			if got := buildNumber(t, dir); got != "6" {
				t.Errorf("build_number.txt holds %q after the build, want 6", got)
			}
			if !strings.Contains(out, "Build complete") {
				t.Errorf("a successful build did not say so:\n%s", out)
			}
		})
	}
}

// A number with leading zeros is decimal. bash would otherwise read "08" as
// octal and fail, and "007" would name the files differently per platform.
func TestLeadingZerosAreReadAsDecimal(t *testing.T) {
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "08")
			out, err := s.run(t, dir, map[string]string{"VERSION": "1.2.3"}, "-windows", "-amd64")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "build", "windows", binary+"_1.2.3.8"+pcapSuffix+"-windows-amd64.exe")); err != nil {
				t.Errorf("binary not named with build 8: %v\n%s", err, out)
			}
			if got := buildNumber(t, dir); got != "9" {
				t.Errorf("build_number.txt holds %q, want 9", got)
			}
		})
	}
}

// BUILD_NUMBER in the environment pins the number and leaves the file alone,
// which is how the release passes the resolved number to every platform. It
// is read the same way as the file, so "007" is 7 everywhere.
func TestPinnedBuildNumberIsNotBumped(t *testing.T) {
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			out, err := s.run(t, dir, map[string]string{"VERSION": "1.2.3", "BUILD_NUMBER": "007"}, "-windows", "-amd64")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "build", "windows", binary+"_1.2.3.7"+pcapSuffix+"-windows-amd64.exe")); err != nil {
				t.Errorf("binary not named with the pinned number: %v\n%s", err, out)
			}
			if got := buildNumber(t, dir); got != "5" {
				t.Errorf("build_number.txt was changed to %q by a pinned build", got)
			}
		})
	}
}

// A compile error ends the script with a failure and without "Build complete".
// build.ps1 used to discard the failure and report success over the missing
// binary, which the release would then have gone looking for.
func TestFailedCompileFailsTheScript(t *testing.T) {
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			f, err := os.OpenFile(filepath.Join(dir, "main.go"), os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("\nthis is not go\n")
			f.Close()

			out, err := s.run(t, dir, map[string]string{"VERSION": "1.2.3"}, "-windows", "-amd64")
			if err == nil {
				t.Fatalf("the script succeeded with a compile error:\n%s", out)
			}
			if !strings.Contains(out, "FAILED") {
				t.Errorf("the failure was not reported:\n%s", out)
			}
			if strings.Contains(out, "Build complete") {
				t.Errorf("a failed build claimed to be complete:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(dir, "build", "windows", binary+"_1.2.3.5"+pcapSuffix+"-windows-amd64.exe")); err == nil {
				t.Error("a binary was left behind by a failed compile")
			}
		})
	}
}

// A package that fails to build ends the script the same way. build.sh used
// to print FAILED and carry on to "Build complete" with exit status 0.
func TestFailedPackagingFailsTheScript(t *testing.T) {
	if fakeNfpm == "" {
		t.Skip("the stand-in nfpm did not build")
	}
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			env := map[string]string{
				"VERSION":        "1.2.3",
				"PATH":           pathWith(filepath.Dir(fakeNfpm)),
				"FAKE_NFPM_EXIT": "3",
			}
			out, err := s.run(t, dir, env, "-linux", "-amd64", "-nopcap", "-deb")
			if err == nil {
				t.Fatalf("the script succeeded with a failed package:\n%s", out)
			}
			if !strings.Contains(out, "FAILED") {
				t.Errorf("the failure was not reported:\n%s", out)
			}
			if strings.Contains(out, "Build complete") {
				t.Errorf("a failed package was reported as complete:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(dir, "build", "linux", binary+"_1.2.3.5-linux-amd64.deb")); err == nil {
				t.Error("a package file exists although packaging failed")
			}
		})
	}
}

// With the real tool, both package formats come out beside the binary, and
// the generated configuration does not outlive the run.
func TestPackagesAreBuiltAndTheConfigIsRemoved(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm is not on PATH")
	}
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			tmp := t.TempDir()
			env := map[string]string{"VERSION": "1.2.3", "TMPDIR": tmp, "TMP": tmp, "TEMP": tmp}
			out, err := s.run(t, dir, env, "-linux", "-amd64", "-nopcap", "-deb", "-rpm")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			for _, ext := range []string{"deb", "rpm"} {
				pkg := filepath.Join(dir, "build", "linux", binary+"_1.2.3.5-linux-amd64."+ext)
				st, err := os.Stat(pkg)
				if err != nil {
					t.Errorf("%s: %v\n%s", ext, err, out)
					continue
				}
				if st.Size() == 0 {
					t.Errorf("%s package is empty", ext)
				}
			}
			left, _ := filepath.Glob(filepath.Join(tmp, "nfpm_*"))
			if len(left) > 0 {
				t.Errorf("nfpm configuration left in the temp directory: %v", left)
			}
		})
	}
}

// go install leaves nfpm in GOBIN, which is not always on PATH; the script
// looks there before giving up on a tool that is already installed.
func TestNfpmIsFoundInGoBin(t *testing.T) {
	if fakeNfpm == "" {
		t.Skip("the stand-in nfpm did not build")
	}
	path, ok := restrictedPath(t)
	if !ok {
		t.Skip("nfpm is on every PATH this host can be given")
	}
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			gobin := filepath.Join(t.TempDir(), "gobin")
			if err := os.MkdirAll(gobin, 0o700); err != nil {
				t.Fatal(err)
			}
			copyFile(t, fakeNfpm, filepath.Join(gobin, filepath.Base(fakeNfpm)))
			if err := os.Chmod(filepath.Join(gobin, filepath.Base(fakeNfpm)), 0o700); err != nil {
				t.Fatal(err)
			}
			env := map[string]string{"VERSION": "1.2.3", "PATH": path, "GOBIN": gobin}
			out, err := s.run(t, dir, env, "-linux", "-amd64", "-nopcap", "-deb")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(out, "nfpm:") || !strings.Contains(out, "found") {
				t.Errorf("the tool in GOBIN was not reported as found:\n%s", out)
			}
			if strings.Contains(out, "auto-installing") {
				t.Errorf("an installed tool was installed again:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(dir, "build", "linux", binary+"_1.2.3.5-linux-amd64.deb")); err != nil {
				t.Errorf("the package was not written: %v\n%s", err, out)
			}
		})
	}
}

// When nfpm is nowhere and cannot be installed, the script says so and stops.
// build.sh used to silence the install and let set -e end the run with no
// message at all.
func TestNfpmInstallFailureIsReported(t *testing.T) {
	path, ok := restrictedPath(t)
	if !ok {
		t.Skip("nfpm is on every PATH this host can be given")
	}
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			gobin := filepath.Join(t.TempDir(), "gobin")
			if err := os.MkdirAll(gobin, 0o700); err != nil {
				t.Fatal(err)
			}
			// GOPROXY=off makes the install fail at once, offline, wherever
			// the test runs.
			env := map[string]string{"VERSION": "1.2.3", "PATH": path, "GOBIN": gobin, "GOPROXY": "off"}
			out, err := s.run(t, dir, env, "-linux", "-amd64", "-nopcap", "-deb")
			if err == nil {
				t.Fatalf("the script succeeded without nfpm:\n%s", out)
			}
			if !strings.Contains(out, "auto-install failed") || !strings.Contains(out, "Install manually") {
				t.Errorf("the failure was not explained:\n%s", out)
			}
			if !strings.Contains(out, "GOPROXY") {
				t.Errorf("the install's own error was hidden:\n%s", out)
			}
		})
	}
}

// -native builds this host's platform and architecture and nothing else. It
// is what "make build" used to provide before the Makefiles were dropped.
func TestNativeBuildsThisHostOnly(t *testing.T) {
	for _, s := range available(t) {
		t.Run(s.name, func(t *testing.T) {
			dir := copyTree(t)
			setBuildNumber(t, dir, "5")
			out, err := s.run(t, dir, map[string]string{"VERSION": "1.2.3"}, "-native")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			var built []string
			filepath.WalkDir(filepath.Join(dir, "build"), func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					built = append(built, p)
				}
				return nil
			})
			if len(built) != 1 {
				t.Fatalf("-native produced %d files, want exactly 1: %v\n%s", len(built), built, out)
			}
			want := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)
			if !strings.Contains(filepath.Base(built[0]), want) {
				t.Errorf("-native built %q, which does not name this host (%s)", filepath.Base(built[0]), want)
			}
			if filepath.Base(filepath.Dir(built[0])) != runtime.GOOS {
				t.Errorf("-native wrote to %q, want a %s/ subdirectory", built[0], runtime.GOOS)
			}
		})
	}
}
