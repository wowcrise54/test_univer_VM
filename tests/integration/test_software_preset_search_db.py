"""Software presets search names literally by substring on PostgreSQL."""

import pytest

from app import db

pytestmark = pytest.mark.integration
SOFTWARE_PRESETS = [
    "software",
    "software-by-version",
    "software-search",
    "windows-software",
    "windows-software-by-version",
    "windows-software-search",
]


@pytest.fixture
def software_inventory(test_db):
    now = db.now_utc()
    inventories = {
        "linux": [
            ("GitLab CE", "16.1"),
            ("GitLab EE", "17.1"),
            ("Magit", "3.3"),
            ("nginx", "1.2"),
            ("100% Agent", "1"),
            ("100X Agent", "1"),
            ("Agent_tool", "1"),
            ("AgentXtool", "1"),
            ("Agent\\helper", "1"),
            ("AgentXhelper", "1"),
            ("O'Reilly agent", "1"),
        ],
        "windows": [("GitLab CE", "16.2"), ("Git", "2.4"), ("nginx", "1.3")],
    }
    with db.connect() as conn:
        for asset_id, software in inventories.items():
            conn.execute(
                "INSERT INTO asset_cards(asset_id,display_name,os_name,first_seen,last_seen) VALUES(%s,%s,%s,%s,%s)",
                (asset_id, asset_id, "Windows" if asset_id == "windows" else "Linux", now, now),
            )
            card = {
                "asset_id": asset_id,
                "os_name": "Windows" if asset_id == "windows" else "Linux",
                "collections": [
                    {
                        "path": "asset.Host.Softs",
                        "items": [{"data": {"Name": name, "Version": version}} for name, version in software],
                    }
                ],
            }
            assert db.replace_asset_card_software_inventory(conn, asset_id, card, now) == len(software)


@pytest.mark.parametrize("preset_id", SOFTWARE_PRESETS)
def test_software_presets_find_partial_names_case_insensitively(software_inventory, preset_id):
    result = db.query_asset_card_preset(preset_id, software_name=" GIT ", software_version_like="")
    expected = {"GitLab CE", "Git"} if preset_id.startswith("windows-") else {"GitLab CE", "GitLab EE", "Git", "Magit"}
    assert {row["soft_name"] for row in result["rows"]} == expected
    assert result["execution"] == "local" and result["source"] == "asset_cards"
    if preset_id == "software":
        assert next(row for row in result["rows"] if row["soft_name"] == "GitLab CE")["count"] == 2


@pytest.mark.parametrize(
    "name,expected",
    [
        ("lab", {"GitLab CE", "GitLab EE"}),
        ("gitlab ce", {"GitLab CE"}),
        ("%", {"100% Agent"}),
        ("_", {"Agent_tool"}),
        ("\\", {"Agent\\helper"}),
        ("'Reilly", {"O'Reilly agent"}),
        ("' OR 1=1 --", set()),
    ],
)
def test_search_matches_any_part_and_treats_sql_metacharacters_literally(software_inventory, name, expected):
    result = db.query_asset_card_preset("software-search", software_name=name, software_version_like="")
    assert {row["soft_name"] for row in result["rows"]} == expected


@pytest.mark.parametrize(
    "preset_id,versions",
    [
        ("software-search", {"16.1", "16.2"}),
        ("windows-software-search", {"16.2"}),
    ],
)
def test_partial_name_search_still_applies_version_mask_and_windows_scope(software_inventory, preset_id, versions):
    result = db.query_asset_card_preset(preset_id, software_name="git", software_version_like="16.%")
    assert {row["soft_name"] for row in result["rows"]} == {"GitLab CE"}
    assert {row["soft_version"] for row in result["rows"]} == versions


def test_group_drilldown_uses_the_exact_selected_product_not_the_search_substring(software_inventory):
    result = db.query_asset_card_preset_assets("software", software_name="Git")
    assert [row["asset_id"] for row in result["rows"]] == ["windows"]
    assert result["rows"][0]["soft_name"] == "Git"
    ce = db.query_asset_card_preset_assets("software-by-version", software_name="GitLab CE", software_version="16.1")
    assert [row["asset_id"] for row in ce["rows"]] == ["linux"]
