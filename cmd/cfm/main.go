package main

import "fmt"

var Version = "dev"
var BuildTime = "unknown"

func main() {
    fmt.Printf("cfm v%s (built %s)\n", Version, BuildTime)
}
