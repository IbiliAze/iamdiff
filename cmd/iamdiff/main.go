package main

import (
	"context"
	"os"

	"github.com/IbiliAze/iamdiff/internal/cli"

	// Providers register themselves here. Adding a cloud is one import.
	_ "github.com/IbiliAze/iamdiff/internal/provider/aws"
)

func main() {
	os.Exit(cli.Run(context.Background(), cli.Default(), os.Args[1:]))
}
