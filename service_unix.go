//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
)

// runWindowsService заглушка для Unix систем (никогда не вызывается)
func runWindowsService() {
	// Это никогда не должно вызываться на Unix системах
	// так как isServiceMode() возвращает false для не-Windows
	fmt.Println("Windows Service не поддерживается на Unix системах")
	os.Exit(1)
}
