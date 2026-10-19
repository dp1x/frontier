package main

import (
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

func main() {
	data, _ := io.ReadAll(os.Stdin)
	if utf8.Valid(data) {
		fmt.Println("VALID")
	} else {
		fmt.Println("INVALID")
	}
}
