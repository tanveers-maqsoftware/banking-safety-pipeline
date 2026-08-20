from __future__ import annotations

from safety import pii


def test_masks_contextual_account_and_contact_numbers():
    text = (
        "where is my nearest branch? account number 34245345345, "
        "contact no 9583430344"
    )

    result = pii.mask(text, session_id="pii-regression")

    assert "34245345345" not in result.masked_text
    assert "9583430344" not in result.masked_text
    assert [entity.entity_type for entity in result.entities] == [
        "UK_ACCOUNT_NUMBER",
        "PHONE_NUMBER",
    ]
    assert result.account_ref == "ending 5345"
