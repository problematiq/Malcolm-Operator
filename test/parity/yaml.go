package parity

import "sigs.k8s.io/yaml"

func jsonYAML(v any) ([]byte, error) { return yaml.Marshal(v) }
