package main

import (
	"log"
	"os"

	"tuncat/internal/app"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("tuncat: ")

	if len(os.Args) > 1 && os.Args[1] == "obscure" {
		if err := app.RunObscure(); err != nil {
			log.Fatal(err)
		}
		return
	}

	os.Exit(app.Run())
}
