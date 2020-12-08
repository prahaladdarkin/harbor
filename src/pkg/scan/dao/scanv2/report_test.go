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

package scanv2

import (
	"fmt"
	"testing"

	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const sampleReportWithCompleteVulnData = `{
	"generated_at": "2020-08-01T18:28:49.072885592Z",
	"artifact": {
	  "repository": "library/ubuntu",
	  "digest": "sha256:d5b40885539615b9aeb7119516427959a158386af13e00d79a7da43ad1b3fb87",
	  "mime_type": "application/vnd.docker.distribution.manifest.v2+json"
	},
	"scanner": {
	  "name": "Trivy",
	  "vendor": "Aqua Security",
	  "version": "v0.9.1"
	},
	"severity": "Medium",
	"vulnerabilities": [
	  {
		"id": "CVE-2019-18276",
		"package": "bash",
		"version": "5.0-6ubuntu1.1",
		"severity": "Low",
		"description": "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
		"links": [
		  "http://packetstormsecurity.com/files/155498/Bash-5.0-Patch-11-Privilege-Escalation.html",
		  "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18276",
		  "https://github.com/bminor/bash/commit/951bdaad7a18cc0dc1036bba86b18b90874d39ff",
		  "https://security.netapp.com/advisory/ntap-20200430-0003/",
		  "https://www.youtube.com/watch?v=-wGtxJ8opa8"
		],
		"layer": {
		  "digest": "sha256:4739cd2f4f486596c583c79f6033f1a9dee019389d512603609494678c8ccd53",
		  "diff_id": "sha256:f66829086c450acd5f67d0529a58f7120926c890f04e17aa7f0e9365da86480a"
		},
		"cwe_ids": ["CWE-476", "CWE-345"],
		"cvss":{
			"score_v3": 3.2,
			"score_v2": 2.3,
			"vector_v3": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			"vector_v2": "AV:L/AC:M/Au:N/C:P/I:N/A:N"
		},
		"vendor_attributes":[ {
			"key": "foo",
			"value": "bar"
		},
		{
			"key": "foo1",
			"value": "bar1"
		}
		]
	  }
	]
}`

// ReportTestSuite is test suite of testing report DAO.
type ReportTestSuite struct {
	suite.Suite
	rpUUID string
}

// TestReport is the entry of ReportTestSuite.
func TestReport(t *testing.T) {
	suite.Run(t, &ReportTestSuite{})
}

// SetupSuite prepares env for test suite.
func (suite *ReportTestSuite) SetupSuite() {
	dao.PrepareTestForPostgresSQL()
	suite.rpUUID = "uuid"
}

// SetupTest prepares env for test case.
func (suite *ReportTestSuite) SetupTest() {
	r := &scan.Report{
		UUID:             "uuid",
		TrackID:          "track-uuid",
		Digest:           "digest1001",
		RegistrationUUID: "ruuid",
		Requester:        "requester",
		MimeType:         v1.MimeTypeNativeReport,
		Status:           job.PendingStatus.String(),
		StatusCode:       job.PendingStatus.Code(),
		Report:           sampleReportWithCompleteVulnData,
	}

	suite.createReport(r)
	vulns := generateVulnerabilityRecordsForReport("uuid", "scannerId1", 10)
	for _, v := range vulns {
		suite.insertVulnRecordForReport("uuid", v)
	}

}

// TearDownTest clears enf for test case.
func (suite *ReportTestSuite) TearDownTest() {

	reports, err := scan.ListReports(&q.Query{})
	require.NoError(suite.T(), err)
	for _, report := range reports {
		suite.cleanUpAdditionalData(report.UUID, report.RegistrationUUID)
	}
}

// TestVulnerabilityRecordsListForReport tests listing of vulnerability record for reports
func (suite *ReportTestSuite) TestVulnerabilityRecordsListForReport() {
	// create a second report and associate the same  vulnerability record set to the report
	r := &scan.Report{
		UUID:             "uuid1",
		TrackID:          "track-uuid",
		Digest:           "digest1002",
		RegistrationUUID: "scannerId2",
		Requester:        "requester",
		MimeType:         v1.MimeTypeNativeReport,
		Status:           job.PendingStatus.String(),
		StatusCode:       job.PendingStatus.Code(),
		Report:           sampleReportWithCompleteVulnData,
	}
	suite.createReport(r)
	// insert a set of vulnerability records for this report. the vulnerability records
	// belong to the same scanner
	vulns := generateVulnerabilityRecordsForReport("uuid1", "scannerId2", 10)
	for _, v := range vulns {
		suite.insertVulnRecordForReport("uuid1", v)
	}

	// fetch the records for the first report. Additionally assert that these records
	// indeed belong to the same report being fetched and not to another report
	{
		fetchedReportIds := make(map[string]bool)
		vulns, err := GetAllVulnerabilityRecordsForReport("uuid")
		require.NoError(suite.T(), err, "Error when fetching vulnerability records for report")
		require.True(suite.T(), len(vulns) > 0)
		for _, v := range vulns {
			fetchedReportIds[v.Report] = true
		}
		require.True(suite.T(), len(fetchedReportIds) == 1, "More than one fetched report id found")
		for k := range fetchedReportIds {
			require.Equal(suite.T(), "uuid", k, "Report ID mismatch")
		}
	}
	{
		fetchedReportIds := make(map[string]bool)
		vulns, err := GetAllVulnerabilityRecordsForReport("uuid1")
		require.NoError(suite.T(), err, "Error when fetching vulnerability records for report")
		require.True(suite.T(), len(vulns) > 0)
		for _, v := range vulns {
			fetchedReportIds[v.Report] = true
		}
		require.True(suite.T(), len(fetchedReportIds) == 1, "More than one fetched report id found")
		for k := range fetchedReportIds {
			require.Equal(suite.T(), "uuid1", k, "Report ID mismatch")
		}
	}

}

// TestGetVulnerabilityRecordsForScanner gets vulnerability records for scanner
func (suite *ReportTestSuite) TestGetVulnerabilityRecordsForScanner() {

	vulns, err := GetVulnerabilityRecordsForScanner("scannerId1")
	require.NoError(suite.T(), err, "Error when fetching vulnerability records for report")
	require.True(suite.T(), len(vulns) > 0)
}

// TestGetVulnerabilityRecordIdsForScanner gets vulnerability records for scanner
func (suite *ReportTestSuite) TestGetVulnerabilityRecordIdsForScanner() {
	vulns, err := GetVulnerabilityRecordIdsForScanner("scannerId1")
	require.NoError(suite.T(), err, "Error when fetching vulnerability records for report")
	require.True(suite.T(), len(vulns) > 0)
}

func (suite *ReportTestSuite) createReport(r *scan.Report) {
	id, err := scan.CreateReport(r)
	require.NoError(suite.T(), err)
	require.Condition(suite.T(), func() (success bool) {
		success = id > 0
		return
	})
}

func (suite *ReportTestSuite) insertVulnRecordForReport(reportUUID string, vr *VulnerabilityRecord) {
	id, err := InsertVulnerabilityDataForReport(reportUUID, vr)
	require.NoError(suite.T(), err)
	require.True(suite.T(), id > 0, "Failed to insert vulnerability record row for report %s", reportUUID)
}

func (suite *ReportTestSuite) cleanUpAdditionalData(reportID string, scannerID string) {
	err := scan.DeleteReport(reportID)
	require.NoError(suite.T(), err)
	delCount, err := DeleteAllVulnerabilityRecordsForReport(reportID)
	require.NoError(suite.T(), err, "Failed to cleanup records")
	require.True(suite.T(), delCount > 0, "Failed to delete records")
}

func generateVulnerabilityRecordsForReport(reportUUID string, registrationUUID string, numRecords int) []*VulnerabilityRecord {
	vulns := make([]*VulnerabilityRecord, 0)
	for i := 1; i <= numRecords; i++ {
		vulnV2 := new(VulnerabilityRecord)
		vulnV2.CVEID = fmt.Sprintf("CVE-ID%d", i)
		vulnV2.Package = fmt.Sprintf("Package%d", i)
		vulnV2.PackageVersion = "NotAvailable"
		vulnV2.Digest = fmt.Sprintf("ArtifactDigest%d", i)
		vulnV2.PackageType = "Unknown"
		vulnV2.Fix = "1.0.0"
		vulnV2.URL = "url1"
		vulnV2.RegistrationUUID = registrationUUID
		if i%2 == 0 {
			vulnV2.Severity = "High"
		} else if i%3 == 0 {
			vulnV2.Severity = "Medium"
		} else if i%4 == 0 {
			vulnV2.Severity = "Critical"
		} else {
			vulnV2.Severity = "Low"
		}

		vulnV2.Report = reportUUID

		vulns = append(vulns, vulnV2)
	}

	return vulns
}
