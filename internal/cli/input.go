package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ReadPassword prompts for a hidden password.
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return pass, err
}

// ReadConfirmed reads a password twice and checks they match.
func ReadConfirmed() ([]byte, error) {
	p1, err := ReadPassword("Password: ")
	if err != nil {
		return nil, err
	}
	p2, err := ReadPassword("Confirm:  ")
	if err != nil {
		return nil, err
	}
	if string(p1) != string(p2) {
		return nil, fmt.Errorf("passwords do not match")
	}
	return p1, nil
}

// Confirm asks for YES confirmation.
func Confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt+" [YES/no]: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.ToUpper(scanner.Text()) == "YES"
}
