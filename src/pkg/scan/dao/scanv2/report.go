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

	"github.com/astaxie/beego/orm"
	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/lib/q"
)

func init() {
	orm.RegisterModel(new(VulnerabilityRecord), new(ReportVulnerabilityRecord))
}

// CreateVulnerabilityRecord creates new vulnerability record.
func CreateVulnerabilityRecord(vr *VulnerabilityRecord) (int64, error) {
	o := dao.GetOrmer()
	_, vrID, err := o.ReadOrCreate(vr, "CVEID", "RegistrationUUID", "Digest", "Package", "PackageVersion")

	return vrID, err
}

//DeleteVulnerabilityRecord deletes a vulnerability record
func DeleteVulnerabilityRecord(vr *VulnerabilityRecord) error {
	o := dao.GetOrmer()
	_, err := o.Delete(vr, "CVEID", "RegistrationUUID")

	return err
}

// ListVulnerabilityRecords lists the vulnerability records with given query parameters.
// Keywords in query here will be enforced with `exact` way.
// If the registration ID (which = the scanner ID is not specified), the results
// would contain duplicate records for a CVE depending upon the number of registered
// scanners which individually store data about the CVE. In such cases, it is the
// responsibility of the calling code to de-duplicate the CVE records or bucket them
// per registered scanner
func ListVulnerabilityRecords(query *q.Query) ([]*VulnerabilityRecord, error) {
	o := dao.GetOrmer()
	qt := o.QueryTable(new(VulnerabilityRecord))

	if query != nil {
		if len(query.Keywords) > 0 {
			for k, v := range query.Keywords {
				if vv, ok := v.([]interface{}); ok {
					qt = qt.Filter(fmt.Sprintf("%s__in", k), vv...)
					continue
				}

				qt = qt.Filter(k, v)
			}
		}

		if query.PageNumber > 0 && query.PageSize > 0 {
			qt = qt.Limit(query.PageSize, (query.PageNumber-1)*query.PageSize)
		}
	}

	l := make([]*VulnerabilityRecord, 0)
	_, err := qt.All(&l)

	return l, err
}

//InsertVulnerabilityDataForReport inserts a vulnerability record in the context of scan report
func InsertVulnerabilityDataForReport(reportUUID string, vr *VulnerabilityRecord) (int64, error) {

	vrID, err := CreateVulnerabilityRecord(vr)

	if err != nil {
		return vrID, err
	}

	rvr := new(ReportVulnerabilityRecord)
	rvr.Report = reportUUID
	rvr.VulnRecordID = vrID

	o := dao.GetOrmer()
	_, rvrID, err := o.ReadOrCreate(rvr, "report_uuid", "vuln_record_id")

	return rvrID, err

}

//DeleteAllVulnerabilityRecordsForReport deletes the vulnerability records for a single report
func DeleteAllVulnerabilityRecordsForReport(reportUUID string) (int64, error) {
	o := dao.GetOrmer()
	delCount, err := o.Delete(&ReportVulnerabilityRecord{Report: reportUUID}, "report_uuid")
	return delCount, err
}

// GetAllVulnerabilityRecordsForReport gets all the vulnerability records for a report
func GetAllVulnerabilityRecordsForReport(reportUUID string) ([]*VulnerabilityRecord, error) {
	vulnRecs := make([]*VulnerabilityRecord, 0)
	o := dao.GetOrmer()
	query := `select vulnerability_record_v2.* from vulnerability_record_v2 
			  inner join report_vulnerability_record_v2 on 
			  vulnerability_record_v2.id = report_vulnerability_record_v2.vuln_record_id and report_vulnerability_record_v2.report_uuid=?`
	_, err := o.Raw(query, reportUUID).QueryRows(&vulnRecs)
	return vulnRecs, err
}

// GetVulnerabilityRecordsForScanner gets all the vulnerability records known to a scanner
// identified by registrationUUID
func GetVulnerabilityRecordsForScanner(registrationUUID string) ([]*VulnerabilityRecord, error) {
	var vulnRecs []*VulnerabilityRecord
	o := dao.GetOrmer()
	vulRec := new(VulnerabilityRecord)
	qs := o.QueryTable(vulRec)
	_, err := qs.Filter("registration_uuid", registrationUUID).All(&vulnRecs)
	if err != nil {
		return nil, err
	}
	return vulnRecs, nil
}

// DeleteVulnerabilityRecordsForScanner deletes all the vulnerability records for a given scanner
// identified by registrationUUID
func DeleteVulnerabilityRecordsForScanner(registrationUUID string) (int64, error) {
	o := dao.GetOrmer()
	vulnRec := new(VulnerabilityRecord)
	vulnRec.RegistrationUUID = registrationUUID
	return o.Delete(vulnRec, "registration_uuid")
}

// GetVulnerabilityRecordIdsForScanner retrieves the internal Ids of the vulnerability records for a given scanner
// identified by registrationUUID
func GetVulnerabilityRecordIdsForScanner(registrationUUID string) ([]int, error) {
	vulnRecordIds := make([]int, 0)
	o := dao.GetOrmer()
	_, err := o.Raw("select id from vulnerability_record_v2 where registration_uuid = ?", registrationUUID).QueryRows(&vulnRecordIds)
	if err != nil {
		return vulnRecordIds, err
	}
	return vulnRecordIds, err
}
