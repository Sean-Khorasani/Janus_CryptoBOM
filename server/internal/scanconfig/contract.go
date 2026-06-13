package scanconfig

const (
	DefaultScanIntervalSeconds uint64 = 15 * 60
	MinScanIntervalSeconds     uint64 = 10
	MaxScanIntervalSeconds     uint64 = 7 * 24 * 60 * 60

	DefaultMaxFileBytes   uint64 = 2 * 1024 * 1024
	DefaultMaxBinaryBytes uint64 = 16 * 1024 * 1024
	MinScanBytes          uint64 = 1024
	MaxScanBytes          uint64 = 10 * 1024 * 1024 * 1024
)

type Range struct {
	Min uint64 `json:"min"`
	Max uint64 `json:"max"`
}

type Defaults struct {
	ScanIntervalSeconds uint64 `json:"scan_interval_seconds"`
	MaxFileBytes        uint64 `json:"max_file_bytes"`
	MaxBinaryBytes      uint64 `json:"max_binary_bytes"`
}

type Limits struct {
	ScanIntervalSeconds Range `json:"scan_interval_seconds"`
	ScanBytes           Range `json:"scan_bytes"`
}

type Schema struct {
	Defaults Defaults `json:"defaults"`
	Limits   Limits   `json:"limits"`
}

func CurrentSchema() Schema {
	return Schema{
		Defaults: Defaults{
			ScanIntervalSeconds: DefaultScanIntervalSeconds,
			MaxFileBytes:        DefaultMaxFileBytes,
			MaxBinaryBytes:      DefaultMaxBinaryBytes,
		},
		Limits: Limits{
			ScanIntervalSeconds: Range{Min: MinScanIntervalSeconds, Max: MaxScanIntervalSeconds},
			ScanBytes:           Range{Min: MinScanBytes, Max: MaxScanBytes},
		},
	}
}
