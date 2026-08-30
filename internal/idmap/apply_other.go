//go:build !linux

package idmap

import "fmt"

func Apply([]Spec) error        { return fmt.Errorf("idmapped mounts require Linux") }
func ApplyCurrent([]Spec) error { return fmt.Errorf("idmapped mounts require Linux") }
