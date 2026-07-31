package profile

import (
	"embed"
	"fmt"
)

//go:embed profiles/*.toml
var embedded embed.FS

func builtins() (Registry, error) {
	reg := Registry{}
	entries, err := embedded.ReadDir("profiles")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		path := "profiles/" + e.Name()
		data, err := embedded.ReadFile(path)
		if err != nil {
			return nil, err
		}
		layer, err := parse(data, "builtin:"+e.Name(), true)
		if err != nil {
			return nil, fmt.Errorf("builtin profile %s: %w", e.Name(), err)
		}
		if err := reg.merge(layer); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
