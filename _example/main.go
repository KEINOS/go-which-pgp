package main

import (
	"fmt"
	"io"
	"os"

	"github.com/KEINOS/go-which-pgp/whichpgp"
)

// --- Demo CLI ---
func main() {
	// Read entire stdin as the ASCII-armored key text
	all, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	flavor, ver, err := whichpgp.DetectFlavorFromArmor(string(all))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("Detected: %s (packet version v%d)\n", flavor, ver)
}
