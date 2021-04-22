package main

import "testing"

func TestGetPackages(t *testing.T) {
	t.Log(GetRPMPackage("/proc/1083009/root"))
}
