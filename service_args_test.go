package main

import "testing"

func TestServiceCommandArgsDoesNotPassRegistryKey(t *testing.T) {
	got := serviceCommandArgs(`C:\Program Files\winssh\frpc.toml`)
	if len(got) != 2 {
		t.Fatalf("serviceCommandArgs() = %#v, want exactly config flag and path", got)
	}
	if got[0] != "-c" || got[1] != `C:\Program Files\winssh\frpc.toml` {
		t.Fatalf("serviceCommandArgs() = %#v, want -c and exact config path", got)
	}
	for _, arg := range got {
		if arg == "-k" || arg == "--key" {
			t.Fatalf("registry-key flag must not be passed to the service: %#v", got)
		}
	}
}
