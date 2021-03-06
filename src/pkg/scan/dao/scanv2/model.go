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

import "time"

// Report of the scan. This report model confirms to the new Common Vulnerability Schema Specification
// Identified by the `digest`, `registration_uuid` and `mime_type`.
type Report struct {
	ID               int64     `orm:"pk;auto;column(id)"`
	UUID             string    `orm:"unique;column(uuid)"`
	Digest           string    `orm:"column(digest)"`
	RegistrationUUID string    `orm:"column(registration_uuid)"`
	MimeType         string    `orm:"column(mime_type)"`
	JobID            string    `orm:"column(job_id)"`
	TrackID          string    `orm:"column(track_id)"`
	Requester        string    `orm:"column(requester)"`
	Status           string    `orm:"column(status)"`
	StatusCode       int       `orm:"column(status_code)"`
	StatusRevision   int64     `orm:"column(status_rev)"`
	StartTime        time.Time `orm:"column(start_time);auto_now_add;type(datetime)"`
	EndTime          time.Time `orm:"column(end_time);type(datetime)"`
}

// VulnerabilityRecord identifies an  individual vulnerability item in the scan.
// Identified by the `cve_id`.
// Relates to the image using the `digest` and to the report using the `report UUID` field
type VulnerabilityRecord struct {
	ID               int64    `orm:"pk;auto;column(id)"`
	CVEID            string   `orm:"unique;column(cve_id)"`
	Digest           string   `orm:"column(digest)"`
	Report           string   `orm:"column(report_uuid)"`
	ScannerID        string   `orm:"column(registration_id)"`
	Package          string   `orm:"column(package)"`
	PackageType      string   `orm:"column(package_type)"`
	Severity         string   `orm:"column(severity)"`
	Fix              string   `orm:"column(fixed_version)"`
	URL              []string `orm:"column(urls)"`
	CVE3Score        string   `orm:"column(cve3_score)"`
	CVE2Score        string   `orm:"column(cve2_score)"`
	Description      string   `orm:"column(description)"`
	VendorAttributes string   `orm:"column(vendoratribtes);type(json)"`
	CVSS3Vector      string   `orm:"column(cvss3_vector);null"`
	CVSS2Vector      string   `orm:"column(cvss3_vector);null"`
}

//ReportVulnerability is relation table required to optimize data storage for both the
//vulnerability records and the scan report.
//identified by composite key (ID, Report)
//Since each scan report has a separate UUID, the composite key
//would ensure that the immutability of the historical scan reports is guaranteed
type ReportVulnerability struct {
	ID     int64  `orm:"pk;auto;column(id)"`
	Report string `orm:"column(report_uuid);"`
}

//CVSS3Vector is table that would store the CVSS 3.x related attack vectors
//Identified uniquely by CVSS3VectorUUID
//Also identified by composite key (CVEID, SourceUUID).
type CVSS3Vector struct {
	ID                         int64  `orm:"pk;auto;column(id)"`
	CVEID                      string `orm:"unique;column(cve_id)"`
	SourceUUID                 string `orm:"column(source_uuid)"`
	CVSS3VectorUUID            string `orm:"unique;column(vector_uuid)"`
	BaseAV                     int8   `orm:"column(base_av)"`
	BaseAC                     int8   `orm:"column(base_ac)"`
	BasePR                     int8   `orm:"column(base_pr)"`
	BaseUI                     int8   `orm:"column(base_ui)"`
	Scope                      int8   `orm:"column(scope)"`
	Confidentiality            int8   `orm:"column(confidentiality)"`
	Integrity                  int8   `orm:"column(integrity)"`
	Availability               int8   `orm:"column(availability)"`
	ExploitMaturity            int8   `orm:"column(exploit_maturity);null"`
	RemediationLevel           int8   `orm:"column(remediation_level);null"`
	ReportConfidence           int8   `orm:"column(report_confidence);null"`
	ConfidentialityRequirement int8   `orm:"column(confidentiality_requirement);null"`
	IntegrityRequirement       int8   `orm:"column(integrity_requirement);null"`
	AvailabilityRequirement    int8   `orm:"column(availability_requirement);null"`
	ModifiedAV                 int8   `orm:"column(modified_av);null"`
	ModifiedAC                 int8   `orm:"column(modified_ac);null"`
	ModifiedPR                 int8   `orm:"column(modified_pr);null"`
	ModifiedUI                 int8   `orm:"column(modified_ui);null"`
	ModifiedScope              int8   `orm:"column(modified_scope);null"`
	ModifiedConfidentiality    int8   `orm:"column(modified_confidentiality);null"`
	ModifiedIntegrity          int8   `orm:"column(modified_integrity);null"`
	ModifiedAvailability       int8   `orm:"column(modified_availability);null"`
}

//CVSS2Vector is table that would store the CVSS 2.x related attack vectors
//Identified uniquely by CVSS2VectorUUID.
//Also identified by a composite key (CVEID, SourceUUID)
//CVSS2 metrics are similar to CVSS 3.x metrics, however there are some
//fields that are not part of CVSS3.x
type CVSS2Vector struct {
	ID                         int64  `orm:"pk;auto;column(id)"`
	CVEID                      string `orm:"unique;column(cve_id)"`
	SourceUUID                 string `orm:"column(source_uuid)"`
	CVSS2VectorUUID            string `orm:"unique;column(vector_uuid)"`
	BaseAV                     int8   `orm:"column(base_av)"`
	BaseAC                     int8   `orm:"column(base_ac)"`
	BaseAU                     int8   `orm:"column(base_pr)"`
	Confidentiality            int8   `orm:"column(confidentiality)"`
	Integrity                  int8   `orm:"column(integrity)"`
	Availability               int8   `orm:"column(availability)"`
	ExploitMaturity            int8   `orm:"column(exploit_maturity);null"`
	RemediationLevel           int8   `orm:"column(remediation_level);null"`
	ReportConfidence           int8   `orm:"column(report_confidence);null"`
	CollateralDamagePotential  int8   `orm:"column(collateral_damage_potential);null"`
	TargetDistribution         int8   `orm:"column(target_distribution);null"`
	ConfidentialityRequirement int8   `orm:"column(confidentiality_requirement);null"`
	IntegrityRequirement       int8   `orm:"column(integrity_requirement);null"`
	AvailabilityRequirement    int8   `orm:"column(availability_requirement);null"`
}

//CVSSSource  is  a table that would store the known sources of CVSS information
//Known sources would typically be the Vendor of the package or the distribution
//or NVD
type CVSSSource struct {
	ID         int64  `orm:"pk;auto;column(id)"`
	SourceUUID string `orm:"column(source)"`
	SourceName string `orm:"column(source_id)"`
}

// TableName for Report
func (r *Report) TableName() string {
	return "scan_report"
}

// TableUnique for Report
func (r *Report) TableUnique() [][]string {
	return [][]string{
		{"uuid"},
		{"digest", "registration_uuid", "mime_type"},
	}
}
