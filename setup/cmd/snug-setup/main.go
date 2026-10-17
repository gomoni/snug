// Command snug-setup suggests a snug profile for a project directory and
// writes it once you agree.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `usage: snug-setup [--print] [--offline] [--profile-dir DIR] [--name NAME] [DIR]
`

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug-setup: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run() (int, error) {
	fs := flag.NewFlagSet("snug-setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.Bool("print", false, "")
	fs.Bool("offline", false, "")
	fs.String("profile-dir", "", "")
	fs.String("name", "", "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usage)
			return 0, nil
		}
		fmt.Fprint(os.Stderr, usage)
		return 1, err
	}
	return 1, errors.New("not implemented")
}
