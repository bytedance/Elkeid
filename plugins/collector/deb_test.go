package main

import "testing"

func TestGetDebPackages(t *testing.T) {
	t.Log(GetDebPackage("/proc/1085113/root"))
}
