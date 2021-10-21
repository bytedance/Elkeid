package main

import "testing"

func TestGetSystemdUnit(t *testing.T) {
	units, err := GetSystemdUnit()
	t.Logf("%+v %+v", units, err)
}
