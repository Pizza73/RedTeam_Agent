"""Closed, reviewable operation catalog.

Every entry fixes the executable family and argv prefix. Runtime input can fill
only the declared parameter slots; it can never supply a subcommand or option.
"""
# ruff: noqa: E501

from __future__ import annotations

from ad_mcp.models import ParameterKind, ParameterSpec, Risk, ToolDefinition

CATALOG_REVISION = "ad-mcp-catalog-v1"

TIMEOUT = ParameterSpec(
    name="timeout_seconds", kind=ParameterKind.INTEGER, minimum=1, maximum=86_400
)
DOMAIN = ParameterSpec(
    name="domain", kind=ParameterKind.STRING, flag="--domain", pattern=r"^[A-Za-z0-9.-]{1,253}$"
)
USERNAME = ParameterSpec(
    name="username", kind=ParameterKind.STRING, flag="--username", pattern=r"^[^\x00\r\n]{1,256}$"
)
CREDENTIAL = ParameterSpec(
    name="credential",
    kind=ParameterKind.SECRET,
    flag="--password",
    required=True,
    sensitive=True,
)
INPUT_RESOURCE = ParameterSpec(
    name="input_resource", kind=ParameterKind.RESOURCE, required=True
)


def _tool(
    name: str,
    category: str,
    binary: str,
    prefix: tuple[str, ...],
    risk: Risk,
    description: str,
    *,
    parameters: tuple[ParameterSpec, ...] = (),
    detections: tuple[str, ...] = (),
    parser: str = "generic-lines-v1",
    target: bool = True,
    remote: bool = False,
    timeout: int = 300,
    output: int = 16 * 1024 * 1024,
    version: str = "configured-and-hash-pinned",
) -> ToolDefinition:
    note = (
        "Risk classification requires user approval before enablement."
        if risk is Risk.UNCLASSIFIED
        else None
    )
    return ToolDefinition(
        operation_id=name,
        mcp_name=name,
        category=category,
        binary_id=binary,
        supported_version=version,
        argv_prefix=prefix,
        parameters=(*parameters, TIMEOUT),
        risk=risk,
        classification_note=note,
        description=description,
        parser_id=parser,
        detection_ids=detections,
        default_timeout_seconds=timeout,
        max_output_bytes=output,
        network_target_required=target,
        remote_windows=remote,
    )


_U = Risk.UNCLASSIFIED
_I = Risk.INTRUSIVE

TOOLS: tuple[ToolDefinition, ...] = (
    # Recon. These risks remain unclassified because the approved specification
    # explicitly left the ping/recon classification open.
    _tool("recon.nmap.smb_security_mode", "recon", "nmap", ("-Pn", "-p445", "--script", "smb2-security-mode"), _U, "Inspect SMB signing mode.", detections=("AD.SMB_SIGNING",), parser="nmap-v1"),
    _tool("recon.nmap.smb_protocols", "recon", "nmap", ("-Pn", "-p445", "--script", "smb-protocols"), _U, "Inspect enabled SMB protocol versions.", parser="nmap-v1"),
    _tool("recon.nmap.smb_enum_shares", "recon", "nmap", ("-Pn", "-p445", "--script", "smb-enum-shares"), _U, "Enumerate SMB shares with a fixed NSE script.", parser="nmap-v1"),
    _tool("recon.nmap.ldap_rootdse", "recon", "nmap", ("-Pn", "-p389", "--script", "ldap-rootdse"), _U, "Read LDAP RootDSE with a fixed NSE script.", detections=("AD.LDAP_ANONYMOUS",), parser="nmap-v1"),
    _tool("recon.nmap.krb5_enum_users", "recon", "nmap", ("-Pn", "-p88", "--script", "krb5-enum-users"), _U, "Run the fixed Kerberos user enumeration script.", parameters=(DOMAIN, INPUT_RESOURCE), parser="nmap-v1"),
    _tool("recon.nxc.smb", "recon", "nxc", ("smb",), _U, "Discover SMB hosts and signing configuration.", detections=("AD.SMB_SIGNING",), parser="nxc-v1"),
    _tool("recon.nxc.ldap", "recon", "nxc", ("ldap",), _U, "Discover LDAP services.", detections=("AD.LDAP_SIGNING", "AD.LDAP_CHANNEL_BINDING"), parser="nxc-v1"),
    _tool("recon.nxc.winrm", "recon", "nxc", ("winrm",), _U, "Discover WinRM services.", parser="nxc-v1"),
    # Enumeration.
    _tool("enumeration.enum4linux.all", "enumeration", "enum4linux-ng", ("-A",), _U, "Run the fixed enum4linux-ng enumeration profile.", detections=("AD.SMB_ANONYMOUS", "AD.PASSWORD_POLICY"), parser="enum4linux-v1"),
    _tool("enumeration.rpcclient.enumdomusers", "enumeration", "rpcclient", ("-N", "-c", "enumdomusers"), _U, "Enumerate domain users through the fixed rpcclient command.", parser="rpcclient-v1"),
    _tool("enumeration.rpcclient.querydominfo", "enumeration", "rpcclient", ("-N", "-c", "querydominfo"), _U, "Read domain information through rpcclient.", detections=("AD.PASSWORD_POLICY",), parser="rpcclient-v1"),
    _tool("enumeration.smbclient.list", "enumeration", "smbclient", ("-N", "-L"), _U, "List SMB shares without accepting an internal smbclient command.", parser="smbclient-v1"),
    _tool("enumeration.smbmap.list", "enumeration", "smbmap", (), _U, "List SMB share access.", parameters=(USERNAME,), parser="smbmap-v1"),
    _tool("enumeration.ldapsearch.rootdse", "enumeration", "ldapsearch", ("-LLL", "-x", "-s", "base"), _U, "Read a bounded LDAP RootDSE view.", parser="ldap-v1"),
    _tool("enumeration.windapsearch.domain_admins", "enumeration", "windapsearch", ("--da",), _U, "Enumerate domain administrators.", parameters=(DOMAIN, USERNAME), detections=("AD.PRIVILEGED_GROUPS",), parser="ldap-v1"),
    _tool("enumeration.ldapdomaindump", "enumeration", "ldapdomaindump", ("--no-html", "--no-grep"), _U, "Collect bounded LDAP domain records.", parameters=(DOMAIN, USERNAME), parser="ldapdomaindump-v1"),
    _tool("enumeration.bloodhound.collect", "enumeration", "bloodhound-python", ("-c", "DCOnly,ObjectProps,ACL"), _U, "Collect the fixed BloodHound data set.", parameters=(DOMAIN, USERNAME), detections=("AD.DELEGATION", "AD.EXCESSIVE_ACL", "AD.PRIVILEGED_GROUPS"), parser="bloodhound-collector-v1", output=128 * 1024 * 1024),
    _tool("enumeration.adidnsdump", "enumeration", "adidnsdump", ("--print-zones",), _U, "Enumerate AD-integrated DNS records.", parameters=(DOMAIN, USERNAME), parser="adidns-v1"),
    # Kerberos.
    _tool("kerberos.kerbrute.userenum", "kerberos", "kerbrute", ("userenum",), _U, "Enumerate Kerberos principals from an approved resource.", parameters=(DOMAIN, INPUT_RESOURCE), parser="kerbrute-v1"),
    _tool("kerberos.kerbrute.passwordspray", "kerberos", "kerbrute", ("passwordspray",), _U, "Run a bounded Kerberos password spray.", parameters=(DOMAIN, INPUT_RESOURCE, CREDENTIAL), parser="kerbrute-v1"),
    _tool("kerberos.impacket.getnpusers", "kerberos", "impacket-GetNPUsers", ("-request",), _U, "Identify AS-REP roast exposure.", parameters=(DOMAIN, USERNAME), detections=("AD.ASREP_ROAST",), parser="impacket-kerberos-v1"),
    _tool("kerberos.impacket.getuserspns", "kerberos", "impacket-GetUserSPNs", ("-request",), _U, "Identify Kerberoast exposure.", parameters=(DOMAIN, USERNAME), detections=("AD.KERBEROAST",), parser="impacket-kerberos-v1"),
    _tool("kerberos.impacket.gettgt", "kerberos", "impacket-getTGT", (), _U, "Request a TGT for an approved principal.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-kerberos-v1"),
    _tool("kerberos.impacket.getst", "kerberos", "impacket-getST", (), _U, "Request a service ticket with fixed operation semantics.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-kerberos-v1"),
    _tool("kerberos.impacket.ticketer", "kerberos", "impacket-ticketer", (), _I, "Create an explicitly approved test ticket.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-kerberos-v1", target=False),
    _tool("kerberos.impacket.ticketconverter", "kerberos", "impacket-ticketConverter", (), _U, "Convert an approved ticket artifact.", parameters=(INPUT_RESOURCE,), parser="artifact-v1", target=False),
    _tool("kerberos.impacket.describeticket", "kerberos", "impacket-describeTicket", (), _U, "Describe an approved ticket artifact.", parameters=(INPUT_RESOURCE,), parser="artifact-v1", target=False),
    _tool("kerberos.impacket.raisechild", "kerberos", "impacket-raiseChild", (), _I, "Run the fixed raiseChild workflow.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-kerberos-v1"),
    _tool("kerberos.impacket.goldenpac", "kerberos", "impacket-goldenPac", (), _I, "Run the fixed goldenPac validation workflow.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-kerberos-v1"),
    # AD CS. Risk values are explicitly specified by the approved requirements.
    _tool("adcs.certipy.find", "adcs", "certipy", ("find", "-json"), Risk.ACTIVE, "Enumerate AD CS configuration.", parameters=(DOMAIN, USERNAME, CREDENTIAL), detections=tuple(f"AD.ADCS_ESC{i}" for i in range(1, 9)), parser="certipy-find-v1"),
    _tool("adcs.certipy.cert", "adcs", "certipy", ("cert",), Risk.PASSIVE, "Inspect an approved certificate artifact.", parameters=(INPUT_RESOURCE,), parser="certipy-v1", target=False),
    *tuple(_tool(f"adcs.certipy.{name}", "adcs", "certipy", (name,), _I, f"Run the fixed Certipy {name} operation.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="certipy-v1") for name in ("req", "auth", "shadow", "template", "ca", "account", "relay", "forge")),
    # Secrets and remote execution.
    *tuple(_tool(f"secrets.impacket.{name.lower()}", "secrets", f"impacket-{name}", (), _I, f"Run the fixed Impacket {name} operation.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-exec-v1") for name in ("secretsdump", "psexec", "smbexec", "wmiexec", "atexec", "dcomexec", "mssqlclient")),
    # AD changes and additional Impacket enumeration.
    *tuple(_tool(f"ad_change.impacket.{name.lower()}", "ad-change", f"impacket-{name}", (), _I, f"Run the fixed Impacket {name} directory change.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-change-v1") for name in ("addcomputer", "rbcd", "dacledit", "owneredit", "changepasswd")),
    _tool("enumeration.impacket.finddelegation", "enumeration", "impacket-findDelegation", (), Risk.ACTIVE, "Enumerate delegation relationships.", parameters=(DOMAIN, USERNAME, CREDENTIAL), detections=("AD.DELEGATION",), parser="impacket-enum-v1"),
    *tuple(_tool(f"enumeration.impacket.{name.lower()}", "enumeration", f"impacket-{name}", (), _U, f"Run the fixed Impacket {name} read operation.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="impacket-enum-v1") for name in ("GetADUsers", "samrdump", "lookupsid", "netview", "rpcdump", "reg", "services")),
    # Coercion and relay.
    _tool("coercion.ntlmrelayx", "coercion-relay", "impacket-ntlmrelayx", (), _I, "Run a fixed NTLM relay listener profile.", parameters=(DOMAIN,), detections=("AD.COERCION_EXPOSURE",), parser="relay-v1", timeout=3600),
    _tool("coercion.responder", "coercion-relay", "responder", ("-A",), _I, "Run the registered Responder assessment profile.", detections=("AD.COERCION_EXPOSURE",), parser="responder-v1", timeout=3600),
    _tool("coercion.coercer", "coercion-relay", "Coercer", ("scan",), _I, "Check registered coercion paths.", parameters=(DOMAIN, USERNAME, CREDENTIAL), detections=("AD.COERCION_EXPOSURE",), parser="coercer-v1"),
    _tool("coercion.petitpotam", "coercion-relay", "PetitPotam", (), _I, "Check the registered PetitPotam path.", parameters=(DOMAIN, USERNAME, CREDENTIAL), detections=("AD.COERCION_EXPOSURE",), parser="coercer-v1"),
    # Offline cracking and bounded authentication tests.
    _tool("cracking.hashcat.dictionary", "cracking", "hashcat", ("--quiet", "--status", "--status-json"), _U, "Run hashcat on approved resource files.", parameters=(INPUT_RESOURCE,), parser="cracking-v1", target=False, timeout=86_400),
    _tool("cracking.john.dictionary", "cracking", "john", ("--show=left",), _U, "Run John on an approved hash resource.", parameters=(INPUT_RESOURCE,), parser="cracking-v1", target=False, timeout=86_400),
    *tuple(_tool(f"authentication.nxc.{protocol}_spray", "authentication", "nxc", (protocol,), _U, f"Run a bounded NetExec {protocol} authentication test.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="nxc-v1") for protocol in ("smb", "ldap", "winrm")),
    # BloodHound analysis. The query identifier is an enum; raw Cypher is never accepted.
    _tool("analysis.bloodhound.import", "analysis", "bloodhound-ce-client", ("import",), _U, "Import an approved BloodHound archive.", parameters=(INPUT_RESOURCE,), parser="bloodhound-api-v1", target=False),
    _tool("analysis.bloodhound.query", "analysis", "bloodhound-ce-client", ("query",), _U, "Run one registered BloodHound query.", parameters=(ParameterSpec(name="query_id", kind=ParameterKind.ENUM, flag="--query-id", required=True, choices=("shortest_paths_to_da", "unconstrained_delegation", "dangerous_acls", "privileged_groups")),), detections=("AD.DELEGATION", "AD.EXCESSIVE_ACL", "AD.PRIVILEGED_GROUPS"), parser="bloodhound-api-v1", target=False),
    # Registered Windows payload operations. A concrete transport remains disabled
    # until the user selects it; dry-run and manifest verification still work.
    *tuple(_tool(f"privesc.rubeus.{name}", "privesc", "Rubeus.exe", (name,), _I, f"Run registered Rubeus {name} on Windows.", parameters=(DOMAIN, USERNAME, CREDENTIAL), parser="windows-payload-v1", remote=True) for name in ("asktgt", "kerberoast", "asreproast", "s4u", "tgtdeleg", "ptt")),
    _tool("privesc.powerup.invoke_allchecks", "privesc", "PowerUp.ps1", ("Invoke-AllChecks",), _I, "Run the registered PowerUp checks.", parser="windows-payload-v1", remote=True),
    _tool("privesc.godpotato.run", "privesc", "GodPotato.exe", (), _I, "Run the registered GodPotato validation operation.", parser="windows-payload-v1", remote=True),
)

BY_NAME = {tool.mcp_name: tool for tool in TOOLS}
if len(BY_NAME) != len(TOOLS):  # pragma: no cover - import-time invariant
    raise RuntimeError("duplicate AD MCP tool name")


def get_tool(name: str) -> ToolDefinition:
    try:
        return BY_NAME[name]
    except KeyError as exc:
        raise KeyError("unknown AD MCP operation") from exc


def input_schema(tool: ToolDefinition) -> dict[str, object]:
    """Return the exact MCP input schema for one registered operation."""
    parameter_properties: dict[str, object] = {}
    parameter_required: list[str] = []
    for spec in tool.parameters:
        if spec.name in {"domain", "username"}:
            continue
        schema: dict[str, object]
        if spec.kind is ParameterKind.INTEGER:
            schema = {"type": "integer"}
            if spec.minimum is not None:
                schema["minimum"] = spec.minimum
            if spec.maximum is not None:
                schema["maximum"] = spec.maximum
        elif spec.kind is ParameterKind.BOOLEAN:
            schema = {"type": "boolean"}
        elif spec.kind is ParameterKind.ENUM:
            schema = {"type": "string", "enum": list(spec.choices)}
        elif spec.kind is ParameterKind.SECRET:
            schema = {
                "type": "object",
                "properties": {
                    "secret_version_id": {"type": "string", "minLength": 1},
                    "secret_version": {"type": "string", "minLength": 1},
                    "principal_ref": {"type": "string", "minLength": 1},
                    "credential_type": {
                        "type": "string",
                        "enum": ["password", "ntlm_hash", "aes_key", "private_key"],
                    },
                },
                "required": [
                    "secret_version_id",
                    "secret_version",
                    "principal_ref",
                    "credential_type",
                ],
                "additionalProperties": False,
            }
        else:
            schema = {"type": "string", "minLength": 1, "maxLength": 4096}
            if spec.pattern is not None:
                schema["pattern"] = spec.pattern
        parameter_properties[spec.name] = schema
        if spec.required:
            parameter_required.append(spec.name)
    call_schema: dict[str, object] = {
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "maxItems": 64,
                "default": [],
            },
            "domain": {"type": ["string", "null"], "maxLength": 253},
            "username": {"type": ["string", "null"], "maxLength": 256},
            "parameters": {
                "type": "object",
                "properties": parameter_properties,
                "required": parameter_required,
                "additionalProperties": False,
            },
            "dry_run": {"type": "boolean", "default": False},
        },
        "required": ["targets", "parameters", "dry_run"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {"call": call_schema},
        "required": ["call"],
        "additionalProperties": False,
    }
