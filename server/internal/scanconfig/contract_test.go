package scanconfig

import "testing"

func TestCurrentSchemaMatchesContract(t *testing.T) {
	schema := CurrentSchema()

	if schema.Defaults.ScanIntervalSeconds != DefaultScanIntervalSeconds ||
		schema.Defaults.MaxFileBytes != DefaultMaxFileBytes ||
		schema.Defaults.MaxBinaryBytes != DefaultMaxBinaryBytes {
		t.Fatal("schema defaults do not match the scan configuration contract")
	}
	if schema.Limits.ScanIntervalSeconds.Min != MinScanIntervalSeconds ||
		schema.Limits.ScanIntervalSeconds.Max != MaxScanIntervalSeconds ||
		schema.Limits.ScanBytes.Min != MinScanBytes ||
		schema.Limits.ScanBytes.Max != MaxScanBytes {
		t.Fatal("schema limits do not match the scan configuration contract")
	}
}
