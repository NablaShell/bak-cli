package cli

import (
	"fmt"
	"os"
)

// Args holds parsed command-line arguments.
type Args struct {
	Lock    string
	Unlock  string
	Output  string
	Duress  string
	Verbose bool
}

// Parse parses os.Args.
func Parse() *Args {
	a := &Args{}

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--lock":
			if i+1 < len(os.Args) {
				a.Lock = os.Args[i+1]
				i++
			}
		case "--unlock":
			if i+1 < len(os.Args) {
				a.Unlock = os.Args[i+1]
				i++
			}
		case "--output", "-o":
			if i+1 < len(os.Args) {
				a.Output = os.Args[i+1]
				i++
			}
		case "--duress":
			if i+1 < len(os.Args) {
				a.Duress = os.Args[i+1]
				i++
			}
		case "--verbose", "-v":
			a.Verbose = true
		case "--help", "-h":
			usage()
			os.Exit(0)
		}
	}

	if a.Output == "" {
		a.Output = "vault.bak"
	}

	return a
}

func usage() {
	fmt.Println(`bak-cli — encrypted directory archiver

USAGE
  bak-cli --lock <dir>     Seal a directory into a vault
  bak-cli --unlock <file>  Restore a vault

OPTIONS
  --output, -o <path>  Vault file path (default: vault.bak)
  --duress <password>  Emergency password that destroys the vault
  --verbose, -v        Print detailed progress
  --help, -h           Show this message`)
}
