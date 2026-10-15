import pytest

from icheck.services.mib_ingestion import extract_mib_collector_input


ACME_MIB = """ACME-SENSORS-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises, OBJECT-TYPE, MODULE-IDENTITY
        FROM SNMPv2-SMI;

acmeSensors MODULE-IDENTITY
    LAST-UPDATED "202609290000Z"
    ORGANIZATION "ACME Lab"
    DESCRIPTION "Module metadata that must not enter model context."
    ::= { enterprises 424242 }

acmeObjects OBJECT IDENTIFIER ::= { acmeSensors 1 }

acmeTemperature OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Temperature -- this is text, not a comment."
    ::= { acmeObjects 1 }

acmeSensorTable OBJECT-TYPE
    SYNTAX SEQUENCE OF AcmeSensorEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Sensor table."
    ::= { acmeObjects 2 }

END
"""


def test_mib_ingestion_resolves_and_minimizes_safe_symbol_metadata():
    result = extract_mib_collector_input(ACME_MIB)

    assert result.provenance["module_name"] == "ACME-SENSORS-MIB"
    assert result.provenance["parser"] == "icheck_smi_subset_v1"
    assert result.provenance["resolved_symbol_count"] == 4
    assert len(result.provenance["document_sha256"]) == 64
    assert result.provenance["imported_modules"] == ["SNMPv2-SMI"]
    symbols = {
        item["name"]: item for item in result.sample_document["symbols"]
    }
    assert symbols["acmeSensors"]["oid"] == "1.3.6.1.4.1.424242"
    assert symbols["acmeObjects"]["oid"] == "1.3.6.1.4.1.424242.1"
    assert symbols["acmeTemperature"] == {
        "name": "acmeTemperature",
        "kind": "object_type",
        "oid": "1.3.6.1.4.1.424242.1.1",
        "syntax": "Integer32",
        "access": "read-only",
        "index_symbols": [],
    }
    assert "DESCRIPTION" not in str(result.sample_document)
    assert "Module metadata" not in str(result.sample_document)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("NOT A MIB", "exactly one SMI module"),
        (
            "ONE DEFINITIONS ::= BEGIN\n"
            "root OBJECT IDENTIFIER ::= { unknownParent 1 }\nEND\n",
            "no locally resolvable",
        ),
        (
            "ONE DEFINITIONS ::= BEGIN\n"
            "root OBJECT IDENTIFIER ::= { enterprises 1 }\n"
            "root OBJECT IDENTIFIER ::= { enterprises 2 }\nEND\n",
            "duplicate symbol",
        ),
        (
            "ONE DEFINITIONS ::= BEGIN\n"
            "root OBJECT IDENTIFIER ::= { enterprises 1 }\n",
            "terminate with END",
        ),
        (
            "ONE DEFINITIONS ::= BEGIN\n"
            "root OBJECT IDENTIFIER ::= { enterprises 1 }\nEND\n\x00",
            "control characters",
        ),
    ],
)
def test_mib_ingestion_fails_closed_for_ambiguous_inputs(document, message):
    with pytest.raises(ValueError, match=message):
        extract_mib_collector_input(document)
