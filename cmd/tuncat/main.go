package main

import (
	"log"
	"os"

	"github.com/WarrDoge/tuncat/internal/cli"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("tuncat: ")

	if len(os.Args) > 1 && os.Args[1] == "obscure" {
		if err := cli.RunObscure(); err != nil {
			log.Fatal(err)
		}
		return
	}

	os.Exit(cli.Run())
}
