"""PostgreSQL normalization shared by bootstrap and the risk migration.

Only the observed top-level ``exploit`` JSON boolean is supported. Text,
nested values, other vendor fields and malformed payloads remain unknown.
Conflicting explicit sources also remain unknown; no source wins arbitrarily.
"""

BOOLEAN_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION risk_exploit_boolean(payload text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE value jsonb;
BEGIN
    BEGIN value := payload::jsonb;
    EXCEPTION WHEN data_exception THEN RETURN NULL;
    END;
    IF jsonb_typeof(value->'exploit') = 'boolean' THEN
        RETURN (value->>'exploit')::boolean;
    END IF;
    RETURN NULL;
END $$
"""

STATE_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION risk_exploit_state(detail text, metrics text, record text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN COUNT(DISTINCT value)=1 THEN bool_or(value) ELSE NULL END
    FROM (VALUES (risk_exploit_boolean(detail)), (risk_exploit_boolean(metrics)),
        (risk_exploit_boolean(record))) AS evidence(value)
$$
"""

SOURCE_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION risk_exploit_source(detail text, metrics text, record text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN risk_exploit_state(detail,metrics,record) IS NOT NULL THEN
        concat_ws(',', CASE WHEN risk_exploit_boolean(detail) IS NOT NULL THEN 'raw_detail_json:exploit' END,
            CASE WHEN risk_exploit_boolean(metrics) IS NOT NULL THEN 'metrics_json:exploit' END,
            CASE WHEN risk_exploit_boolean(record) IS NOT NULL THEN 'raw_record_json:exploit' END)
        ELSE NULL END
$$
"""

FUNCTIONS_SQL = (BOOLEAN_FUNCTION_SQL, STATE_FUNCTION_SQL, SOURCE_FUNCTION_SQL)
EVIDENCE_COLUMNS = (
    """exploitation_evidence BOOLEAN GENERATED ALWAYS AS (
    risk_exploit_state(raw_detail_json,metrics_json,raw_record_json)
) STORED""",
    """exploitation_evidence_source TEXT GENERATED ALWAYS AS (
    risk_exploit_source(raw_detail_json,metrics_json,raw_record_json)
) STORED""",
)
EVIDENCE_COLUMNS_SQL = ",\n".join(EVIDENCE_COLUMNS)
