package main

import (
	"bufio"
	"fmt"
	"os"
)

func cmdLogin(rest []string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v (do not pass the key on the command line)", rest)
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("do not run login as root; run as the user that runs agentguard up")
	}

	fi, _ := os.Stdin.Stat()
	if fi != nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "Paste ANTHROPIC_API_KEY (input hidden in this prompt is not required); one line, then Enter:\n")
	}

	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return err
		}
		return fmt.Errorf("no key on stdin")
	}
	if err := writeAnthropicAPIKey(sc.Text()); err != nil {
		return err
	}
	path, err := anthropicKeyPath()
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", path)
	return nil
}
