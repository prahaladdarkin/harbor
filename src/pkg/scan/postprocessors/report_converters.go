// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package postprocessors

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scanv2"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

// ScanReportV1Converter is an interface that establishes the contract for the conversion process of a V1 report
// The implementing conversion process need not return any value other than the report UUID.
// It is the responsibility of the implementation to store the report in a manner easily retrievable using the
// report UUID
type ScanReportV1Converter interface {
	Convert(report *scan.Report) (string, error)
}

// ScanReportV1ToV2Converter is responsible for converting the scan report from the V1 format to
// the V2 format which follows a normalized storage schema.
type scanReportV1ToV2Converter struct {
}

// NewScanReportV1ToV2Converter returns a new instance of a V1 report to V2 report converter
func NewScanReportV1ToV2Converter() ScanReportV1Converter {
	return &scanReportV1ToV2Converter{}
}

// Convert converts the Report instance compatble with V1 schema to a Report and VulnerabilityRecord instance
// compatible with the V2 schema
func (c *scanReportV1ToV2Converter) Convert(reportV1 *scan.Report) (string, error) {

	if len(reportV1.Report) == 0 {
		log.Infof("There is no vulnerability report to convert for report UUID : %s", reportV1.UUID)
		return reportV1.UUID, nil
	}

	// parse the raw report with the V1 schema of the report to the normalized structures
	var rawReport vuln.Report
	if err := json.Unmarshal([]byte(reportV1.Report), &rawReport); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("Error when convert V1 report to V2"))
	}

	if err := c.convertRawReportToVulnerabilityData(reportV1.UUID, reportV1.RegistrationUUID, reportV1.Digest, reportV1.Report); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("Error when converting vulnerability report"))
	}
	return reportV1.UUID, nil

}

// ConvertRawReportToVulnerabilityData converts a raw report to
// version 2 of the schema
func (c *scanReportV1ToV2Converter) convertRawReportToVulnerabilityData(reportUUID string, registrationUUID string, digest string, rawReportData string) error {

	var vulnReport vuln.Report
	err := json.Unmarshal([]byte(rawReportData), &vulnReport)
	if err != nil {
		return err
	}
	for _, v := range vulnReport.Vulnerabilities {
		vulnV2 := new(scanv2.VulnerabilityRecord)
		vulnV2.CVEID = v.ID
		vulnV2.Package = v.Package
		vulnV2.PackageVersion = v.Version
		vulnV2.Digest = digest
		vulnV2.PackageType = "Unknown"
		vulnV2.Fix = v.FixVersion
		vulnV2.URL = strings.Join(v.Links, ";")
		vulnV2.RegistrationUUID = registrationUUID
		vulnV2.Severity = v.Severity.String()
		vulnV2.Report = reportUUID

		// process the CVSS scores if the data is available
		if (vuln.CVSS{} != v.CVSSDetails) {
			vulnV2.CVE3Score = v.CVSSDetails.ScoreV3
			vulnV2.CVE2Score = v.CVSSDetails.ScoreV2
			vulnV2.CVSS3Vector = v.CVSSDetails.VectorV3
			vulnV2.CVSS2Vector = v.CVSSDetails.VectorV2
		}
		if len(v.CWEIds) > 0 {
			vulnV2.CWEIds = strings.Join(v.CWEIds, ",")
		}

		// marshall the presented vendor attributes as a json string
		if len(v.VendorAttributes) > 0 {
			vendorAttributes, err := json.Marshal(v.VendorAttributes)
			// set the vendor attributes iff unmarshalling is successful
			if err == nil {
				vulnV2.VendorAttributes = string(vendorAttributes)
			}
		}
		_, err = scanv2.InsertVulnerabilityDataForReport(reportUUID, vulnV2)
		if err != nil {
			return err
		}
	}
	log.Infof("Converted %d vulnerability records to the new schema for report ID %s and scanner Id %s", len(vulnReport.Vulnerabilities), reportUUID, registrationUUID)
	return nil
}

// GetNativeV1ReportFromResolvedData returns the native V1 scan report from the resolved
// interface data.
func (c *scanReportV1ToV2Converter) getNativeV1ReportFromResolvedData(ctx job.Context, rp interface{}) (*vuln.Report, error) {
	report, ok := rp.(*vuln.Report)
	if !ok {
		return nil, errors.New("Data cannot be converted to v1 report format")
	}
	ctx.GetLogger().Infof("Converted raw data to report. Count of Vulnerabilities in report : %d", len(report.Vulnerabilities))
	return report, nil
}
