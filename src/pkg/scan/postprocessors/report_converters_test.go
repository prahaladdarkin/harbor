package postprocessors

import (
	"testing"
	"time"

	"github.com/astaxie/beego"
	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scanv2"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const sampleReport = `{
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
		}
	  }
	]
}`

const sampleReportWithCWEAndCVSS = `{
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
		}
	  }
	]
}`

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

type TestReportConverterSuite struct {
	suite.Suite
	rc     ScanReportV1Converter
	rpUUID string
}

// SetupTest prepares env for test cases.
func (suite *TestReportConverterSuite) SetupTest() {

	suite.rpUUID = "reportUUID"
}

func TestReportConverterTests(t *testing.T) {
	suite.Run(t, &TestReportConverterSuite{})
}

func (suite *TestReportConverterSuite) SetupSuite() {

	rp := &scan.Report{
		Digest:           "d1000",
		RegistrationUUID: "ruuid",
		MimeType:         v1.MimeTypeNativeReport,
		TrackID:          "tid001",
		Requester:        "requester",
		Report:           sampleReport,
		StartTime:        time.Now(),
		EndTime:          time.Now().Add(1000),
		UUID:             "reportUUID",
	}

	suite.rc = NewScanReportV1ToV2Converter()
	dao.PrepareTestForPostgresSQL()
	suite.create(rp)
	beego.SetLevel(beego.LevelDebug)
}

// TearDownTest clears test env for test cases.
func (suite *TestReportConverterSuite) TearDownTest() {
	// No delete method defined in manager as no requirement,
	// so, to clear env, call dao method here
	err := scan.DeleteReport(suite.rpUUID)
	require.NoError(suite.T(), err)
	delCount, err := scanv2.DeleteAllVulnerabilityRecordsForReport(suite.rpUUID)
	require.True(suite.T(), delCount > 0, "Failed to delete vulnerability records")
}
func (suite *TestReportConverterSuite) TestConvertReport() {
	rp := &scan.Report{
		Digest:           "d1000",
		RegistrationUUID: "ruuid",
		MimeType:         v1.MimeTypeNativeReport,
		TrackID:          "tid001",
		Requester:        "requester",
		Report:           sampleReport,
		StartTime:        time.Now(),
		EndTime:          time.Now().Add(1000),
		UUID:             "reportUUID",
	}
	ruuid, err := suite.rc.Convert(rp)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), rp.UUID, ruuid)

}

func (suite *TestReportConverterSuite) TestConvertReportWithCWEAndCVSS() {
	rp := &scan.Report{
		Digest:           "d1000",
		RegistrationUUID: "ruuid",
		MimeType:         v1.MimeTypeNativeReport,
		TrackID:          "tid001",
		Requester:        "requester",
		Report:           sampleReportWithCWEAndCVSS,
		StartTime:        time.Now(),
		EndTime:          time.Now().Add(1000),
		UUID:             "reportUUID",
	}
	ruuid, err := suite.rc.Convert(rp)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), rp.UUID, ruuid)

}

func (suite *TestReportConverterSuite) TestConvertReportWithCompleteVulnData() {
	rp := &scan.Report{
		Digest:           "d1000",
		RegistrationUUID: "ruuid",
		MimeType:         v1.MimeTypeNativeReport,
		TrackID:          "tid001",
		Requester:        "requester",
		Report:           sampleReportWithCompleteVulnData,
		StartTime:        time.Now(),
		EndTime:          time.Now().Add(1000),
		UUID:             "reportUUID",
	}
	ruuid, err := suite.rc.Convert(rp)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), rp.UUID, ruuid)

}

func (suite *TestReportConverterSuite) create(r *scan.Report) {
	id, err := scan.CreateReport(r)
	require.NoError(suite.T(), err)
	require.Condition(suite.T(), func() (success bool) {
		success = id > 0
		return
	})
}
