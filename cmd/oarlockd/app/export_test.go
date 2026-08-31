package app

import "github.com/oarlock/oarlock/internal/config"

// MaxSSHConnections is exported for the tests. The mapping from "unset" and "negative"
// to a concrete cap is policy rather than plumbing — an off-by-one that turned "no cap
// configured" into "no cap" would remove a control and pass every other test.
func MaxSSHConnections(cfg *config.Config) int { return maxSSHConnections(cfg) }
