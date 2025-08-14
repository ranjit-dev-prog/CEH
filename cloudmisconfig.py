import json
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

def print_header(text):
    print(Fore.CYAN + Style.BRIGHT + f"\n=== {text} ===" + Style.RESET_ALL)

def color_text(text, severity):
    colors = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.YELLOW + Style.BRIGHT,
        "MEDIUM": Fore.MAGENTA,
        "LOW": Fore.CYAN
    }
    return colors.get(severity, Fore.WHITE) + text + Style.RESET_ALL

def print_issue(issue):
    print(color_text(f"[{issue['severity']}]", issue["severity"]) +
          f" {issue['issue']} on resource: {issue['resource']} (File: {issue.get('file','Unknown')})")
    print(f"    Description: {issue['desc']}")

def load_json_file(filepath):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.RED}Failed to load {filepath}: {e}")
        return None

# --- AWS Checks ---

def check_public_s3_bucket(bucket):
    results = []
    name = bucket.get("Name", "Unknown Bucket")
    acl = bucket.get("ACL", "").lower()
    policy = bucket.get("Policy", "")
    encryption = bucket.get("Encryption", {}).get("Status", "Disabled").lower()

    if acl in ["public-read", "public-read-write"]:
        results.append({
            "issue": "Public S3 Bucket ACL",
            "desc": "Bucket ACL is set to public-read or public-read-write.",
            "severity": "CRITICAL",
            "resource": name
        })

    if policy and ("\"Effect\":\"Allow\"" in policy and "\"Principal\":\"*\"" in policy):
        results.append({
            "issue": "Public S3 Bucket Policy",
            "desc": "Bucket policy allows public access.",
            "severity": "CRITICAL",
            "resource": name
        })

    if encryption == "disabled":
        results.append({
            "issue": "Unencrypted S3 Bucket",
            "desc": "Bucket encryption is disabled.",
            "severity": "HIGH",
            "resource": name
        })

    return results

def check_security_group(sg):
    results = []
    group_id = sg.get("GroupId", "Unknown SG")
    ingress_rules = sg.get("IpPermissions", [])
    for rule in ingress_rules:
        ip_ranges = rule.get("IpRanges", [])
        ipv6_ranges = rule.get("Ipv6Ranges", [])

        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                results.append({
                    "issue": "Open Security Group IPv4",
                    "desc": "Ingress rule allows 0.0.0.0/0 (anywhere) IPv4 traffic.",
                    "severity": "CRITICAL",
                    "resource": group_id
                })

        for ip_range in ipv6_ranges:
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                results.append({
                    "issue": "Open Security Group IPv6",
                    "desc": "Ingress rule allows ::/0 (anywhere) IPv6 traffic.",
                    "severity": "CRITICAL",
                    "resource": group_id
                })
    return results

def check_iam_role(role):
    results = []
    role_name = role.get("RoleName", "Unknown Role")

    policies = role.get("AssumeRolePolicyDocument", {}).get("Statement", [])
    for stmt in policies:
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if effect == "Allow":
            if any(action == "*" or "*" in action for action in actions):
                results.append({
                    "issue": "Wildcard Action in IAM Role",
                    "desc": "IAM Role allows all actions (*) which is risky.",
                    "severity": "HIGH",
                    "resource": role_name
                })
            if any(resource == "*" or "*" in resource for resource in resources):
                results.append({
                    "issue": "Wildcard Resource in IAM Role",
                    "desc": "IAM Role allows all resources (*) which is risky.",
                    "severity": "HIGH",
                    "resource": role_name
                })
    return results

def check_ebs_volume(volume):
    results = []
    vol_id = volume.get("VolumeId", "Unknown Volume")
    encrypted = volume.get("Encrypted", False)

    if not encrypted:
        results.append({
            "issue": "Unencrypted EBS Volume",
            "desc": "EBS Volume encryption is disabled.",
            "severity": "HIGH",
            "resource": vol_id
        })
    return results

def check_rds_instance(rds):
    results = []
    db_id = rds.get("DBInstanceIdentifier", "Unknown RDS")
    vpc_sgs = rds.get("VpcSecurityGroups", [])

    for sg in vpc_sgs:
        sg_id = sg.get("VpcSecurityGroupId", "")
        if sg_id:
            if rds.get("PubliclyAccessible", False):
                results.append({
                    "issue": "Publicly Accessible RDS",
                    "desc": "RDS instance is publicly accessible.",
                    "severity": "HIGH",
                    "resource": db_id
                })
    return results

# --- Azure Checks ---

def check_azure_storage_account(account):
    results = []
    name = account.get("name", "Unknown Storage Account")
    props = account.get("properties", {})

    access = props.get("allowBlobPublicAccess", False)
    if access:
        results.append({
            "issue": "Azure Storage Account Public Access",
            "desc": "Storage account allows public blob access.",
            "severity": "CRITICAL",
            "resource": name
        })

    encryption = props.get("encryption", {}).get("services", {}).get("blob", {}).get("enabled", False)
    if not encryption:
        results.append({
            "issue": "Azure Storage Account Unencrypted",
            "desc": "Storage account blobs are not encrypted.",
            "severity": "HIGH",
            "resource": name
        })
    return results

def check_azure_nsg(nsg):
    results = []
    name = nsg.get("name", "Unknown NSG")
    props = nsg.get("properties", {})
    security_rules = props.get("securityRules", [])

    for rule in security_rules:
        direction = rule.get("direction", "").lower()
        access = rule.get("access", "").lower()
        src_addr = rule.get("sourceAddressPrefix", "")
        if direction == "inbound" and access == "allow" and (src_addr == "0.0.0.0/0" or src_addr == "*"):
            results.append({
                "issue": "Azure NSG Open Inbound Rule",
                "desc": f"Inbound rule allows traffic from {src_addr}.",
                "severity": "CRITICAL",
                "resource": name
            })
    return results

def check_azure_sql_server(sqlserver):
    results = []
    name = sqlserver.get("name", "Unknown SQL Server")
    props = sqlserver.get("properties", {})
    public_access = props.get("publicNetworkAccess", "Disabled")
    if public_access.lower() == "enabled":
        results.append({
            "issue": "Azure SQL Server Public Access Enabled",
            "desc": "SQL Server allows public network access.",
            "severity": "HIGH",
            "resource": name
        })
    return results

def check_azure_disks(disks):
    results = []
    for disk in disks:
        name = disk.get("name", "Unknown Disk")
        props = disk.get("properties", {})
        encryption = props.get("encryption", {}).get("type", "None")
        if encryption == "None":
            results.append({
                "issue": "Azure Disk Unencrypted",
                "desc": "Disk encryption is disabled.",
                "severity": "HIGH",
                "resource": name
            })
    return results

# --- GCP Checks ---

def check_gcp_storage_bucket(bucket):
    results = []
    name = bucket.get("name", "Unknown Bucket")
    iam_config = bucket.get("iamConfiguration", {})
    public_access_prevention = iam_config.get("publicAccessPrevention", "")
    if public_access_prevention.lower() != "enforced":
        results.append({
            "issue": "GCP Storage Bucket Public Access",
            "desc": "Bucket does not enforce public access prevention.",
            "severity": "CRITICAL",
            "resource": name
        })

    encryption = bucket.get("encryption", {})
    if not encryption:
        results.append({
            "issue": "GCP Storage Bucket Unencrypted",
            "desc": "Bucket encryption not configured.",
            "severity": "HIGH",
            "resource": name
        })

    return results

def check_gcp_firewall_rule(rule):
    results = []
    name = rule.get("name", "Unknown Firewall Rule")
    source_ranges = rule.get("sourceRanges", [])
    if any(sr == "0.0.0.0/0" for sr in source_ranges):
        results.append({
            "issue": "GCP Firewall Rule Open to Internet",
            "desc": "Firewall rule allows traffic from anywhere (0.0.0.0/0).",
            "severity": "CRITICAL",
            "resource": name
        })
    return results

def check_gcp_sql_instance(instance):
    results = []
    name = instance.get("name", "Unknown Cloud SQL Instance")
    ip_config = instance.get("ipConfiguration", {})
    public_ip = ip_config.get("ipv4Enabled", False)
    if public_ip:
        results.append({
            "issue": "GCP Cloud SQL Public IP Enabled",
            "desc": "Cloud SQL instance has public IPv4 enabled.",
            "severity": "HIGH",
            "resource": name
        })
    return results

def check_gcp_disk(disk):
    results = []
    name = disk.get("name", "Unknown Disk")
    disk_encryption_key = disk.get("diskEncryptionKey", None)
    if not disk_encryption_key:
        results.append({
            "issue": "GCP Persistent Disk Unencrypted",
            "desc": "Persistent disk is not encrypted with CMEK.",
            "severity": "HIGH",
            "resource": name
        })
    return results

# Analyze single file
def analyze_file(filepath):
    data = load_json_file(filepath)
    if not data:
        return []

    results = []

    aws_keys = {"Buckets", "SecurityGroups", "Roles", "Volumes", "DBInstances"}
    azure_key = "value"
    gcp_key = "items"

    basename = os.path.basename(filepath)

    # AWS
    if isinstance(data, dict) and aws_keys.intersection(data.keys()):
        if "Buckets" in data:
            for bucket in data["Buckets"]:
                results.extend(check_public_s3_bucket(bucket))
        if "SecurityGroups" in data:
            for sg in data["SecurityGroups"]:
                results.extend(check_security_group(sg))
        if "Roles" in data:
            for role in data["Roles"]:
                results.extend(check_iam_role(role))
        if "Volumes" in data:
            for vol in data["Volumes"]:
                results.extend(check_ebs_volume(vol))
        if "DBInstances" in data:
            for rds in data["DBInstances"]:
                results.extend(check_rds_instance(rds))

    # Azure
    if isinstance(data, dict) and azure_key in data:
        resources = data[azure_key]
        for res in resources:
            resource_type = res.get("type", "").lower()
            if "storageaccounts" in resource_type:
                results.extend(check_azure_storage_account(res))
            elif "networksecuritygroups" in resource_type:
                results.extend(check_azure_nsg(res))
            elif "servers" in resource_type and "microsoft.sql" in resource_type:
                results.extend(check_azure_sql_server(res))
            elif "disks" in resource_type:
                results.extend(check_azure_disks([res]))

    # GCP
    if isinstance(data, dict) and gcp_key in data:
        items = data[gcp_key]
        for item in items:
            kind = item.get("kind", "").lower()
            if "storage#bucket" in kind:
                results.extend(check_gcp_storage_bucket(item))
            elif "compute#firewall" in kind:
                results.extend(check_gcp_firewall_rule(item))
            elif "sql#instance" in kind:
                results.extend(check_gcp_sql_instance(item))
            elif "compute#disk" in kind:
                results.extend(check_gcp_disk(item))

    # Add filename to each issue
    for issue in results:
        issue["file"] = basename

    return results

def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."

    if not os.path.isdir(folder):
        print(Fore.RED + f"Directory does not exist: {folder}")
        sys.exit(1)

    json_files = [os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith(".json")]
    if not json_files:
        print(Fore.RED + f"No JSON files found in directory: {folder}")
        sys.exit(1)

    all_issues = []

    for f in json_files:
        print_header(f"Scanning {f} ...")
        issues = analyze_file(f)
        if not issues:
            print(Fore.GREEN + "No misconfigurations found in this file.\n")
        else:
            print(Fore.RED + f"Found {len(issues)} issues in this file:\n")
            for issue in issues:
                print_issue(issue)
        all_issues.extend(issues)

    print_header("Summary Across All Files")
    if not all_issues:
        print(Fore.GREEN + "No misconfigurations found in any files!")
    else:
        print(Fore.RED + f"Total issues found: {len(all_issues)}")
        sev_count = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for issue in all_issues:
            sev_count[issue["severity"]] += 1
        for sev, count in sev_count.items():
            if count:
                print(color_text(f"{sev}: {count}", sev))

    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"cloud_scan_report_{now_str}.json"

    try:
        with open(output_file, "w") as f:
            json.dump(all_issues, f, indent=2)
        print(Fore.CYAN + f"\nCombined report saved to {output_file}")
    except Exception as e:
        print(Fore.RED + f"Failed to save report: {e}")

if __name__ == "__main__":
    main()
