package version

import "fmt"

// These values are overridden by release builds with Go -ldflags -X.
var (
	Version              = "0.14.0"
	BuildDate            = "dev"
	BuildSequence        = "0"
	APIVersion           = "1"
	AgentProtocolVersion = "1"
)

func Full() string {
	if BuildDate == "" || BuildDate == "dev" {
		return Version + "+dev"
	}
	return fmt.Sprintf("%s+%s.%s", Version, BuildDate, BuildSequence)
}
