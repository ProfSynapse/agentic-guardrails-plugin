from pathlib import Path
import sys
import unicodedata

import pytest


ROOT = Path(__file__).resolve().parents[1]
AGW = ROOT / "plugin" / "scripts" / "agw"
sys.path.insert(0, str(AGW))

import path_safety  # noqa: E402


def test_literal_spelling_is_preserved_while_comparison_uses_nfc(tmp_path):
    decomposed = "cafe\u0301.txt"
    identity = path_safety.identify(str(tmp_path / decomposed))
    assert Path(identity.absolute).name == decomposed
    assert identity.unicode_key == unicodedata.normalize(
        "NFC", identity.native_key
    ).casefold()
    assert {item["code"] for item in identity.warnings} == {"non_nfc_path"}


def test_unicode_equivalent_targets_are_rejected(tmp_path):
    composed = tmp_path / "caf\u00e9.txt"
    decomposed = tmp_path / "cafe\u0301.txt"
    with pytest.raises(path_safety.PathSafetyError) as caught:
        path_safety.require_unique([str(composed), str(decomposed)])
    assert caught.value.details["normalization"] == "NFC"


def test_bidi_and_mixed_script_warnings_are_structured(tmp_path):
    target = tmp_path / "a\u0430\u202ereport.txt"
    codes = {item["code"] for item in path_safety.identify(str(target)).warnings}
    assert "bidi_control_in_path" in codes
    assert "mixed_confusable_scripts" in codes
