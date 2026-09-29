from ad_mcp.catalog import BY_NAME, CATALOG_REVISION, TOOLS
from ad_mcp.models import Risk


def test_catalog_is_unique_and_covers_required_families() -> None:
    assert CATALOG_REVISION == "ad-mcp-catalog-v1"
    assert len(TOOLS) == len(BY_NAME) == 78
    expected = {
        "recon.nmap.smb_security_mode",
        "enumeration.bloodhound.collect",
        "kerberos.impacket.getnpusers",
        "adcs.certipy.find",
        "secrets.impacket.secretsdump",
        "ad_change.impacket.rbcd",
        "coercion.ntlmrelayx",
        "cracking.hashcat.dictionary",
        "analysis.bloodhound.query",
        "privesc.rubeus.s4u",
        "privesc.powerup.invoke_allchecks",
        "privesc.godpotato.run",
    }
    assert expected <= set(BY_NAME)


def test_unspecified_risks_are_not_guessed() -> None:
    assert BY_NAME["recon.nmap.smb_security_mode"].risk is Risk.UNCLASSIFIED
    assert BY_NAME["adcs.certipy.find"].risk is Risk.ACTIVE
    assert BY_NAME["adcs.certipy.cert"].risk is Risk.PASSIVE
    assert BY_NAME["coercion.petitpotam"].risk is Risk.INTRUSIVE
