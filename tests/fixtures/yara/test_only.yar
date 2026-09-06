/*
  TEST_ONLY — regla sintetica para validar YARA integration
  No usar en produccion. Severity high para veto determinista.
*/
rule TEST_ONLY_ShadowNet_Fixture_High {
    meta:
        description = "TEST_ONLY fixture for YARA integration tests"
        author = "ShadowNet Defender"
        severity = "high"
        category = "test"
        reference = "TEST_ONLY"
    strings:
        $a = "SHADOWNET_TEST_FIXTURE_123" ascii wide
    condition:
        $a
}

rule TEST_ONLY_Informational_Medium {
    meta:
        description = "TEST_ONLY medium severity should be SUSPICIOUS not MALICIOUS"
        author = "ShadowNet Defender"
        severity = "medium"
        category = "test"
    strings:
        $b = "SHADOWNET_MEDIUM_FIXTURE_456" ascii wide
    condition:
        $b
}
