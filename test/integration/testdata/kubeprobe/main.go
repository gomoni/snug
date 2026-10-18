// Command kubeprobe runs INSIDE a sandbox in the identity.kube integration
// tests. It speaks raw HTTP to snug's proxy on the sandbox's loopback, tries
// to bind the proxy's port, and searches what the sandbox can read for a
// string. Each subcommand prints one line per result; it has no pass/fail of
// its own.
//
//	kubeprobe get PATH [NAME:VALUE ...]   status line and body
//	kubeprobe loop N PATH                 N gets; prints the first non-200
//	kubeprobe upgrade PATH                101 through the proxy, then an echo
//	kubeprobe bind                        tries 127.0.0.1:6443 and 0.0.0.0:6443
//	kubeprobe find HEX                    every readable file holding the bytes
//	                                      HEX decodes to; hex, so the needle is
//	                                      not in this process's own argv
//	kubeprobe dial HOST:PORT              a direct TCP connect
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const proxy = "127.0.0.1:6443"

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "get":
		status, body := get(os.Args[2], os.Args[3:])
		fmt.Printf("STATUS %s\nBODY %s\n", status, body)
	case "loop":
		n, _ := strconv.Atoi(os.Args[2])
		for i := range n {
			status, body := get(os.Args[3], nil)
			if !strings.HasPrefix(status, "200") {
				fmt.Printf("AT %d STATUS %s BODY %s\n", i, status, body)
				return
			}
		}
		fmt.Printf("ALL %d OK\n", n)
	case "upgrade":
		upgrade(os.Args[2])
	case "bind":
		for _, a := range []string{"127.0.0.1:6443", "0.0.0.0:6443"} {
			ln, err := net.Listen("tcp4", a)
			if err == nil {
				ln.Close()
				fmt.Printf("BIND %s OK\n", a)
			} else {
				fmt.Printf("BIND %s %v\n", a, err)
			}
		}
	case "find":
		needle, err := hex.DecodeString(os.Args[2])
		if err != nil || len(needle) == 0 {
			os.Exit(2)
		}
		find(needle)
	case "dial":
		c, err := net.DialTimeout("tcp", os.Args[2], 3*time.Second)
		if err == nil {
			c.Close()
			fmt.Println("DIAL OK")
		} else {
			fmt.Printf("DIAL %v\n", err)
		}
	}
}

func get(path string, headers []string) (string, string) {
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return "DIAL " + err.Error(), ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", path, proxy)
	for _, h := range headers {
		k, v, _ := strings.Cut(h, ":")
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	io.WriteString(c, req.String())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "READ " + err.Error(), ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.Status, strings.TrimSpace(string(b))
}

func upgrade(path string) {
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		fmt.Println("DIAL", err)
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n", path, proxy)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		fmt.Println("READ", err)
		return
	}
	fmt.Println("STATUS", resp.Status)
	if resp.StatusCode != 101 {
		return
	}
	io.WriteString(c, "ping\n")
	line, _ := br.ReadString('\n')
	fmt.Printf("TUNNEL %s", line)
}

// find walks what a payload would: the environment, the home directory, /snug,
// /tmp, and every process's cmdline and environ it can read.
func find(needle []byte) {
	check := func(p string) {
		b, err := os.ReadFile(p)
		if err == nil && bytes.Contains(b, needle) {
			fmt.Println("FOUND", p)
		}
	}
	for _, e := range os.Environ() {
		if strings.Contains(e, string(needle)) {
			fmt.Println("FOUND env", strings.SplitN(e, "=", 2)[0])
		}
	}
	home, _ := os.UserHomeDir()
	for _, root := range []string{home, "/snug", "/tmp", "/run"} {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				check(p)
			}
			return nil
		})
	}
	procs, _ := os.ReadDir("/proc")
	for _, e := range procs {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			check("/proc/" + e.Name() + "/cmdline")
			check("/proc/" + e.Name() + "/environ")
		}
	}
	fmt.Println("FIND DONE")
}
