package main

import "testing"

func TestGetPypiPackage(t *testing.T) {
	t.Log(GetPypiPackage("/proc/1088891/root"))
}
