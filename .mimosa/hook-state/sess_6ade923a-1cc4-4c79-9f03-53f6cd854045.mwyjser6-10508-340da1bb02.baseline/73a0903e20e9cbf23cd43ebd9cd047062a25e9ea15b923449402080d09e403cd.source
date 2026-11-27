"""Match data of vulnerability passports, kept in tables the matcher can index.

Matching findings to passports needs each passport's CVE names and the OS
family named in its text. Deriving both from the raw JSON of the whole catalog
on every asset card save is what made saves slow, so a trigger maintains them
as passports are written.
"""

CVE_NAME_SQL = """
UPPER(COALESCE(
    cve ->> 'display_name', cve ->> 'displayName', cve ->> 'cve',
    cve ->> 'name', cve ->> 'value',
    CASE WHEN jsonb_typeof(cve) = 'string' THEN cve #>> '{}' END,
    ''
))
""".strip()

OS_FAMILY_CASE_SQL = """
CASE
    WHEN search_text ~ 'windows' THEN 'windows'
    WHEN search_text ~ 'ubuntu' THEN 'ubuntu'
    WHEN search_text ~ 'debian' THEN 'debian'
    WHEN search_text ~ 'red hat|redhat|rhel' THEN 'rhel'
    WHEN search_text ~ 'centos' THEN 'centos'
    WHEN search_text ~ 'rocky' THEN 'rocky'
    WHEN search_text ~ 'alma' THEN 'almalinux'
    WHEN search_text ~ 'oracle.*linux' THEN 'oraclelinux'
    WHEN search_text ~ 'astra' THEN 'astra'
    WHEN search_text ~ '(^|[^a-z])alt([^a-z]|$)' THEN 'altlinux'
    WHEN search_text ~ 'suse|sles|opensuse' THEN 'suse'
    ELSE NULL
END
""".strip()

TABLE_SQL = (
    """
    CREATE TABLE IF NOT EXISTS vulnerability_passport_cves (
        passport_internal_id TEXT NOT NULL
            REFERENCES vulnerability_passports(internal_id) ON DELETE CASCADE,
        cve_name TEXT NOT NULL,
        PRIMARY KEY (passport_internal_id, cve_name)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_vulnerability_passport_cves_name "
    "ON vulnerability_passport_cves(cve_name)",
    """
    CREATE TABLE IF NOT EXISTS vulnerability_passport_os_family (
        passport_internal_id TEXT PRIMARY KEY
            REFERENCES vulnerability_passports(internal_id) ON DELETE CASCADE,
        os_family TEXT
    )
    """,
)

# Malformed JSON must not block passport writes, so such rows are skipped.
FUNCTION_SQL = (
    f"""
CREATE OR REPLACE FUNCTION vulnerability_passport_cves_sync() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_family TEXT;
BEGIN
    BEGIN
        DELETE FROM vulnerability_passport_cves WHERE passport_internal_id = NEW.internal_id;
        INSERT INTO vulnerability_passport_cves (passport_internal_id, cve_name)
        SELECT DISTINCT NEW.internal_id, name
        FROM (
            SELECT {CVE_NAME_SQL} AS name
            FROM jsonb_array_elements(COALESCE(NULLIF(NEW.cves_json, ''), '[]')::jsonb) AS cve
        ) AS names
        WHERE name <> '';
    EXCEPTION WHEN others THEN
        NULL;
    END;
    SELECT {OS_FAMILY_CASE_SQL} INTO v_family
    FROM (
        SELECT LOWER(CONCAT_WS(
            ' ', NEW.name, NEW.external_id, NEW.package_id, NEW.package_version,
            NEW.raw_record_json, NEW.raw_detail_json
        )) AS search_text
    ) AS source;
    INSERT INTO vulnerability_passport_os_family (passport_internal_id, os_family)
    VALUES (NEW.internal_id, v_family)
    ON CONFLICT (passport_internal_id) DO UPDATE SET os_family = EXCLUDED.os_family;
    RETURN NEW;
END
$$
""",
)

TRIGGER_SQL = (
    """
    CREATE OR REPLACE TRIGGER trg_vulnerability_passport_cves_sync
    AFTER INSERT OR UPDATE OF
        cves_json, name, external_id, package_id, package_version,
        raw_record_json, raw_detail_json
    ON vulnerability_passports
    FOR EACH ROW EXECUTE FUNCTION vulnerability_passport_cves_sync()
    """,
)

BACKFILL_SQL = (
    f"""
    INSERT INTO vulnerability_passport_cves (passport_internal_id, cve_name)
    SELECT DISTINCT passport.internal_id, names.name
    FROM vulnerability_passports AS passport
    CROSS JOIN LATERAL (
        SELECT {CVE_NAME_SQL} AS name
        FROM jsonb_array_elements(COALESCE(NULLIF(passport.cves_json, ''), '[]')::jsonb) AS cve
    ) AS names
    WHERE names.name <> ''
    ON CONFLICT DO NOTHING
    """,
    f"""
    INSERT INTO vulnerability_passport_os_family (passport_internal_id, os_family)
    SELECT internal_id, {OS_FAMILY_CASE_SQL}
    FROM (
        SELECT internal_id, LOWER(CONCAT_WS(
            ' ', name, external_id, package_id, package_version,
            raw_record_json, raw_detail_json
        )) AS search_text
        FROM vulnerability_passports
    ) AS source
    ON CONFLICT (passport_internal_id) DO UPDATE SET os_family = EXCLUDED.os_family
    """,
)

SCHEMA_SQL = (*TABLE_SQL, *FUNCTION_SQL, *TRIGGER_SQL)
