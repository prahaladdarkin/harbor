package postprocessors

import (
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	mock "github.com/stretchr/testify/mock"
)

// ScanReportV1ToV2Converter is an auto-generated mock type for converting scan V1 report
// to scan V2
type ScanReportV1ToV2Converter struct {
	mock.Mock
}

// Convert is a mock implementation of the scan report conversion
func (_c *ScanReportV1ToV2Converter) Convert(reportV1 *scan.Report) (string, error) {
	return "mockId", nil
}
