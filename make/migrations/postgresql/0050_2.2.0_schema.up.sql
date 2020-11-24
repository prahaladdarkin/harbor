/* 
Fixes issue https://github.com/goharbor/harbor/issues/13317 
  Ensure the role_id of maintainer is 4 and the role_id of limisted guest is 5
*/
UPDATE role SET role_id=4 WHERE name='maintainer' AND role_id!=4;
UPDATE role SET role_id=5 WHERE name='limitedGuest' AND role_id!=5;

ALTER TABLE schedule ADD COLUMN IF NOT EXISTS cron_type varchar(64);
ALTER TABLE robot ADD COLUMN IF NOT EXISTS secret varchar(2048);

DO $$
DECLARE
    art RECORD;
    art_size integer;
BEGIN
    FOR art IN SELECT * FROM artifact WHERE size = 0
    LOOP
      SELECT sum(size) INTO art_size FROM blob WHERE digest IN (SELECT digest_blob FROM artifact_blob WHERE digest_af=art.digest);
      UPDATE artifact SET size=art_size WHERE id = art.id;
    END LOOP;
END $$;

ALTER TABLE robot ADD COLUMN IF NOT EXISTS secret varchar(2048);

CREATE TABLE  IF NOT EXISTS role_permission (
 id SERIAL PRIMARY KEY NOT NULL,
 role_type varchar(255) NOT NULL,
 role_id int NOT NULL,
 permission_policy_id int NOT NULL,
 creation_time timestamp default CURRENT_TIMESTAMP,
 CONSTRAINT unique_role_permission UNIQUE (role_type, role_id, permission_policy_id)
);

CREATE TABLE  IF NOT EXISTS permission_policy (
 id SERIAL PRIMARY KEY NOT NULL,
 /*
  scope:
   system level: /system
   project level: /project/{id}
   all project: /project/ *
  */
 scope varchar(255) NOT NULL,
 resource varchar(255),
 action varchar(255),
 effect varchar(255),
 creation_time timestamp default CURRENT_TIMESTAMP,
 CONSTRAINT unique_rbac_policy UNIQUE (scope, resource, action, effect)
);


/*
Common vulnerability reporting schema.
Github proposal link : https://github.com/goharbor/community/pull/145
*/

-- --------------------------------------------------
--  Table Structure for `main.VulnerabilityRecord`
-- --------------------------------------------------
CREATE TABLE IF NOT EXISTS "vulnerability_record_v2" (
    "id" serial NOT NULL PRIMARY KEY,
    "cve_id" text NOT NULL DEFAULT '' ,
    "registration_uuid" text NOT NULL DEFAULT '',
    "digest" text NOT NULL DEFAULT '' ,
    "report_uuid" text NOT NULL DEFAULT '' ,
    "package" text NOT NULL DEFAULT '' ,
    "package_version" text NOT NULL DEFAULT '' ,
    "package_type" text NOT NULL DEFAULT '' ,
    "severity" text NOT NULL DEFAULT '' ,
    "fixed_version" text,
    "urls" text,
    "cve3_score" double precision,
    "cve2_score" double precision,
    "cvss3_vector" text,
    "cvss2_vector" text,
    "description" text,
    "cwe_ids" text,
    "vendorattributes" json,
    UNIQUE ("cve_id", "registration_uuid", "package", "package_version", "digest")
);

-- --------------------------------------------------
--  Table Structure for `main.ReportVulnerabilityRecord`
-- --------------------------------------------------
CREATE TABLE IF NOT EXISTS "report_vulnerability_record_v2" (
    "id" serial NOT NULL PRIMARY KEY,
    "report_uuid" text NOT NULL DEFAULT '' ,
    "vuln_record_id" bigint NOT NULL DEFAULT 0 ,
    UNIQUE ("report_uuid", "vuln_record_id")
);

