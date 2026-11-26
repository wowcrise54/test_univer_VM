from app.services.wazuh_asset_match import applies_to_version, extract_rules, platform_for


def test_vendor_rules_compare_full_deb_versions():
    rules = extract_rules([{
        "providerMetadata": {"shortName": "canonical"},
        "affected": [{
            "vendor": "canonical",
            "product": "example",
            "platforms": ["noble"],
            "defaultStatus": "unaffected",
            "versions": [{
                "status": "affected", "version": "0",
                "lessThan": "1:2.0-1ubuntu2~24.04.2", "versionType": "custom",
            }],
        }],
    }])
    assert platform_for("Ubuntu", "24.04.5") == ("canonical", "noble")
    assert platform_for("Debian", "12.15") == ("debian", "bookworm")
    vendor, release, name, default, versions = rules[0]
    assert (vendor, release, name) == ("canonical", "noble", "example")
    assert applies_to_version("1:2.0-1ubuntu2~24.04.1", default, versions) is True
    assert applies_to_version("1:2.0-1ubuntu2~24.04.2", default, versions) is False
    assert applies_to_version("invalid", default, versions) is None
