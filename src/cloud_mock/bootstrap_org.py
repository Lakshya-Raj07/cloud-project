import json
import os
import sys
from pathlib import Path
from botocore.exceptions import ClientError

# Ensure UTF-8 output encoding across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure current module directory is on sys.path for direct execution
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from aws_client_factory import get_organizations_client


def bootstrap_cloud_environment():
    client = get_organizations_client()
    print("[*] Initializing AWS Organizations mock environment...")

    # 1. Create Organization if not exists
    try:
        org_resp = client.create_organization(FeatureSet="ALL")
        print(f"[+] Created Organization: {org_resp['Organization']['Id']}")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AlreadyInOrganizationException", "OrganizationAlreadyInUseException"):
            print("[!] Organization already exists. Proceeding...")
        else:
            print(f"[!] Note on create_organization: {e}")

    # 2. Get Root ID
    roots = client.list_roots()["Roots"]
    root_id = roots[0]["Id"]
    print(f"[+] Root OU ID: {root_id}")

    # 3. Enable SCP Policy Type at Root
    try:
        client.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
        print("[+] Enabled SERVICE_CONTROL_POLICY on Root")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "PolicyTypeAlreadyEnabledException":
            print("[!] SERVICE_CONTROL_POLICY already enabled on Root.")
        else:
            print(f"[!] Enable policy type note: {e}")

    # 4. Load Hierarchy Config
    config_dir = Path(__file__).resolve().parent.parent.parent / "config"
    hierarchy_file = config_dir / "org_hierarchy.json"
    with open(hierarchy_file, "r", encoding="utf-8") as f:
        hierarchy_data = json.load(f)

    ou_mapping = {}

    # List any existing OUs under Root
    existing_ous = {
        item["Name"]: item["Id"]
        for item in client.list_organizational_units_for_parent(ParentId=root_id)["OrganizationalUnits"]
    }

    # 5. Create OUs under Root
    for ou_entry in hierarchy_data["organization"]["ous"]:
        ou_name = ou_entry["name"]
        if ou_name in existing_ous:
            ou_id = existing_ous[ou_name]
            print(f"[!] OU {ou_name} exists (ID: {ou_id})")
        else:
            try:
                ou_resp = client.create_organizational_unit(ParentId=root_id, Name=ou_name)
                ou_id = ou_resp["OrganizationalUnit"]["Id"]
                print(f"[+] Created OU: {ou_name} (ID: {ou_id})")
            except Exception as e:
                print(f"[!] Error creating OU {ou_name}: {e}")
                continue

        ou_mapping[ou_name] = {"id": ou_id, "accounts": []}

        # 6. Create Mock Accounts inside OU
        for acct_suffix in ou_entry["accounts"]:
            email = f"tenant_{acct_suffix}@simulation.local"
            try:
                client.create_account(Email=email, AccountName=f"Account-{acct_suffix}")
                accts = client.list_accounts()["Accounts"]
                acct_id = next(a["Id"] for a in accts if a.get("Email") == email)

                # Move account to OU from Root
                try:
                    client.move_account(
                        AccountId=acct_id,
                        SourceParentId=root_id,
                        DestinationParentId=ou_id,
                    )
                    print(f"    |-- Account {acct_id} created & moved to {ou_name}")
                except Exception as move_err:
                    print(f"    |-- Account {acct_id} in {ou_name} (move note: {move_err})")

                ou_mapping[ou_name]["accounts"].append(acct_id)
            except Exception as ex:
                # If already created, find from list_accounts
                try:
                    accts = client.list_accounts()["Accounts"]
                    matched = [a["Id"] for a in accts if a.get("Email") == email]
                    if matched:
                        ou_mapping[ou_name]["accounts"].append(matched[0])
                        print(f"    |-- Account {matched[0]} mapped to {ou_name}")
                    else:
                        ou_mapping[ou_name]["accounts"].append(acct_suffix)
                except Exception:
                    ou_mapping[ou_name]["accounts"].append(acct_suffix)

    # 7. Create Base Template SCP (Baseline AC-SCP Model)
    template_path = config_dir / "scp_templates.json"
    with open(template_path, "r", encoding="utf-8") as f:
        template_doc = json.load(f)

    # Check existing policies to avoid duplicates
    existing_policies = {
        p["Name"]: p["Id"]
        for p in client.list_policies(Filter="SERVICE_CONTROL_POLICY")["Policies"]
    }

    baseline_policy_id = None
    if "AC-SCP-Baseline-Policy" in existing_policies:
        baseline_policy_id = existing_policies["AC-SCP-Baseline-Policy"]
        print(f"[!] Baseline SCP already present: {baseline_policy_id}")
    else:
        try:
            policy_resp = client.create_policy(
                Content=json.dumps(template_doc),
                Description="Base Parameterized SCP Template for Adaptive Control",
                Name="AC-SCP-Baseline-Policy",
                Type="SERVICE_CONTROL_POLICY",
            )
            baseline_policy_id = policy_resp["Policy"]["PolicySummary"]["Id"]
            print(f"[+] Initialized Baseline SCP: {baseline_policy_id}")

            client.attach_policy(PolicyId=baseline_policy_id, TargetId=root_id)
            print(f"[+] Attached Baseline SCP to Root {root_id}")
        except Exception as ex:
            print(f"[!] Error creating baseline SCP: {ex}")

    # 8. Create Advance Static Guardrail SCP (Tag-based)
    static_guardrail_path = config_dir / "static_guardrail_scp.json"
    static_policy_id = None
    if static_guardrail_path.exists():
        with open(static_guardrail_path, "r", encoding="utf-8") as f:
            static_guardrail_doc = json.load(f)

        if "StaticGuardrailSCP" in existing_policies:
            static_policy_id = existing_policies["StaticGuardrailSCP"]
            print(f"[!] Static Guardrail SCP already present: {static_policy_id}")
        else:
            try:
                static_resp = client.create_policy(
                    Content=json.dumps(static_guardrail_doc),
                    Description="Advance Static Guardrail SCP conditioned on PrincipalTag:RiskLevel",
                    Name="StaticGuardrailSCP",
                    Type="SERVICE_CONTROL_POLICY",
                )
                static_policy_id = static_resp["Policy"]["PolicySummary"]["Id"]
                print(f"[+] Initialized Static Guardrail SCP: {static_policy_id}")

                client.attach_policy(PolicyId=static_policy_id, TargetId=root_id)
                print(f"[+] Attached Static Guardrail SCP to Root {root_id}")
            except Exception as ex:
                print(f"[!] Error creating static guardrail SCP: {ex}")

    # 9. Save runtime state for the ML and Benchmark engines
    state_file = config_dir / "runtime_state.json"
    state_data = {
        "root_id": root_id,
        "ous": ou_mapping,
        "policies": {
            "baseline_policy_id": baseline_policy_id,
            "static_guardrail_policy_id": static_policy_id,
        },
    }
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(state_data, f, indent=2)

    print(f"[OK] Runtime cloud state saved to config/runtime_state.json")
    return state_data


if __name__ == "__main__":
    bootstrap_cloud_environment()
