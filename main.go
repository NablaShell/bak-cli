package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/NablaShell/bak-cli/internal/cli"
	"github.com/NablaShell/bak-cli/internal/crypto"
	"github.com/NablaShell/bak-cli/internal/vault"
	"github.com/NablaShell/bak-cli/internal/wipe"
)

func main() {
	args := cli.Parse()

	if args.Lock != "" && args.Unlock != "" {
		fmt.Fprintln(os.Stderr, "Specify --lock or --unlock, not both.")
		os.Exit(1)
	}
	if args.Lock == "" && args.Unlock == "" {
		fmt.Fprintln(os.Stderr, "Use --lock <dir> or --unlock <file>")
		os.Exit(1)
	}

	if args.Lock != "" {
		lock(args)
	} else {
		unlock(args)
	}
}

func lock(args *cli.Args) {
	if _, err := os.Stat(args.Lock); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pass, err := cli.ReadConfirmed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer crypto.Burn(pass)

	chunkSize := detectChunkSize()

	fmt.Fprintf(os.Stderr, "Chunk size: %d MB\n", chunkSize/(1024*1024))

	if err := vault.Pack(args.Lock, args.Output, pass, chunkSize); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Wiping source...")
	if err := wipe.Dir(args.Lock); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: wipe failed: %v\n", err)
	}

	fmt.Println("Done.")
}

func unlock(args *cli.Args) {
	if _, err := os.Stat(args.Unlock); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pass, err := cli.ReadPassword("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer crypto.Burn(pass)

	// Duress.
	if args.Duress != "" && string(pass) == args.Duress {
		if !cli.Confirm("Duress password detected. Destroy vault?") {
			fmt.Println("Cancelled.")
			return
		}
		if err := wipe.File(args.Unlock); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Vault destroyed.")
		return
	}

	// "." — распаковать в текущую директорию
	if err := vault.Unpack(args.Unlock, ".", pass); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done.")
}

// detectChunkSize returns a chunk size based on available memory.
func detectChunkSize() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 256 * 1024 * 1024
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb int64
				// Проверяем, что Sscanf успешно распарсил ровно 1 элемент (G104)
				n, err := fmt.Sscanf(fields[1], "%d", &kb)
				if err != nil || n != 1 {
					// Если парсинг упал, выходим на дефолтные 256МБ
					return 256 * 1024 * 1024
				}

				chunk := int(kb*1024) / 4
				if chunk < 16*1024*1024 {
					chunk = 16 * 1024 * 1024
				}
				if chunk > 1024*1024*1024 {
					chunk = 1024 * 1024 * 1024
				}
				return chunk
			}
		}
	}
	return 256 * 1024 * 1024
}
