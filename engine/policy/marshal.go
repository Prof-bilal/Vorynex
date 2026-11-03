package policy

import "gopkg.in/yaml.v3"

// Marshal encodes the policy as YAML. It lives here (rather than in a
// trace-to-policy generator) so the engine can persist policies without the
// Warden-only starter generator.
func (p Policy) Marshal() ([]byte, error) { return yaml.Marshal(p) }
