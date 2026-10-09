"""Read-only AWS inventory -> Terraform (with import blocks) + a map from AWS ids to Terraform addresses.

The map is what lets Warden fix a resource at runtime AND open a PR against the exact Terraform that owns it,
so code and cloud stay in sync (no drift)."""
import json
import re
from pathlib import Path

import boto3

SKIP_VPC_TAGS = {"warden-demo"}
S3_SCOPE = re.compile(r"^(552455647653-acme-dev-|company-sensitive-data-demo|demo-bucket-|my-unique-bucket-|prowler-test-bucket|prowler-reports-demo)")


def snake(s: str) -> str:
    s = re.sub(r"[^0-9a-zA-Z]+", "_", s).strip("_").lower()
    return ("r_" + s) if s[:1].isdigit() else s


def tags(obj) -> dict:
    return {t["Key"]: t["Value"] for t in obj.get("Tags", []) if not t["Key"].startswith("aws:")}


def hcl_tags(t: dict, ind="  ") -> str:
    if not t:
        return ""
    body = "\n".join(f'{ind}  "{k}" = {json.dumps(v)}' for k, v in sorted(t.items()))
    return f"{ind}tags = {{\n{body}\n{ind}}}\n"


def q(v) -> str:
    return json.dumps(v)


class Gen:
    def __init__(self, profile, region):
        self.s = boto3.Session(profile_name=profile, region_name=region)
        self.ec2, self.s3 = self.s.client("ec2"), self.s.client("s3")
        self.files: dict[str, str] = {}
        self.imports: list[tuple[str, str]] = []
        self.map: dict[str, dict] = {}
        self.names: dict[str, str] = {}  # aws id -> terraform address

    def add(self, file, text):
        self.files[file] = self.files.get(file, "") + text + "\n"

    def reg(self, aws_id, rtype, name, file, import_id=None):
        addr = f"{rtype}.{name}"
        self.names[aws_id] = addr
        self.map[aws_id] = {"address": addr, "file": file}
        self.imports.append((addr, import_id or aws_id))
        return addr

    def run(self):
        vpcs = [v for v in self.ec2.describe_vpcs()["Vpcs"]
                if not (SKIP_VPC_TAGS & set(tags(v))) and not tags(v).get("Name", "").startswith("aws-controltower")]
        vpc_ids = {v["VpcId"] for v in vpcs}
        for v in vpcs:
            n = snake(tags(v).get("Name") or v["VpcId"])
            attr = lambda a: self.ec2.describe_vpc_attribute(VpcId=v["VpcId"], Attribute=a)
            dns_s = attr("enableDnsSupport")["EnableDnsSupport"]["Value"]
            dns_h = attr("enableDnsHostnames")["EnableDnsHostnames"]["Value"]
            self.reg(v["VpcId"], "aws_vpc", n, "network.tf")
            self.add("network.tf", f'resource "aws_vpc" "{n}" {{\n  cidr_block           = {q(v["CidrBlock"])}\n'
                                   f'  enable_dns_support   = {str(dns_s).lower()}\n  enable_dns_hostnames = {str(dns_h).lower()}\n{hcl_tags(tags(v))}}}\n')
        for sn in self.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": list(vpc_ids)}])["Subnets"]:
            n = snake(tags(sn).get("Name") or sn["SubnetId"])
            self.reg(sn["SubnetId"], "aws_subnet", n, "network.tf")
            self.add("network.tf", f'resource "aws_subnet" "{n}" {{\n  vpc_id                  = {self.names[sn["VpcId"]]}.id\n'
                                   f'  cidr_block              = {q(sn["CidrBlock"])}\n  availability_zone       = {q(sn["AvailabilityZone"])}\n'
                                   f'  map_public_ip_on_launch = {str(sn["MapPublicIpOnLaunch"]).lower()}\n{hcl_tags(tags(sn))}}}\n')
        sgs = [g for g in self.ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": list(vpc_ids)}])["SecurityGroups"] if g["GroupName"] != "default"]
        for g in sgs:  # register first so cross-references resolve
            self.reg(g["GroupId"], "aws_security_group", snake(g["GroupName"])[:60], "security_groups.tf")
        for g in sgs:
            self.add("security_groups.tf", self.sg_block(g))
        for a in self.ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": list(vpc_ids)}])["NetworkAcls"]:
            if a["IsDefault"]:
                continue
            n = snake(tags(a).get("Name") or a["NetworkAclId"])
            self.reg(a["NetworkAclId"], "aws_network_acl", n, "network.tf")
            self.add("network.tf", self.nacl_block(n, a))
        for r in self.ec2.describe_instances(Filters=[{"Name": "vpc-id", "Values": list(vpc_ids)}, {"Name": "instance-state-name", "Values": ["running", "stopped"]}])["Reservations"]:
            for i in r["Instances"]:
                self.add("ec2.tf", self.instance_block(i))
        self.s3_buckets()
        self.add("providers.tf", 'terraform {\n  required_version = ">= 1.5"\n  required_providers {\n    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\n\n'
                                 f'provider "aws" {{\n  region = {q(self.s.region_name)}\n}}\n')
        self.files["imports.tf"] = "".join(f'import {{\n  to = {a}\n  id = {q(i)}\n}}\n\n' for a, i in self.imports)
        return self

    def sg_block(self, g) -> str:
        n = self.names[g["GroupId"]].split(".")[1]

        def rules(perms, kind):
            out = []
            for p in perms:
                cidr4 = [r["CidrIp"] for r in p.get("IpRanges", [])]
                cidr6 = [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]
                sgrefs = [self.names.get(x["GroupId"], x["GroupId"]) for x in p.get("UserIdGroupPairs", [])]
                desc = next((r.get("Description") for r in p.get("IpRanges", []) if r.get("Description")), None)
                lines = [f'    from_port   = {p.get("FromPort", 0)}', f'    to_port     = {p.get("ToPort", 0)}', f'    protocol    = {q(p["IpProtocol"])}']
                if cidr4:
                    lines.append(f"    cidr_blocks = {json.dumps(cidr4)}")
                if cidr6:
                    lines.append(f"    ipv6_cidr_blocks = {json.dumps(cidr6)}")
                if sgrefs:
                    lines.append("    security_groups = [" + ", ".join(f"{x}.id" if x.startswith("aws_") else q(x) for x in sgrefs) + "]")
                if desc:
                    lines.append(f"    description = {q(desc)}")
                out.append(f"  {kind} {{\n" + "\n".join(lines) + "\n  }\n")
            return "".join(out)
        return (f'resource "aws_security_group" "{n}" {{\n  name        = {q(g["GroupName"])}\n  description = {q(g["Description"])}\n'
                f'  vpc_id      = {self.names[g["VpcId"]]}.id\n\n{rules(g["IpPermissions"], "ingress")}{rules(g["IpPermissionsEgress"], "egress")}{hcl_tags(tags(g))}}}\n')

    def nacl_block(self, n, a) -> str:
        def entry(kind, egress):
            out = []
            for e in sorted((e for e in a["Entries"] if e["Egress"] == egress and e["RuleNumber"] < 32767), key=lambda e: e["RuleNumber"]):
                pr = e["PortRange"] if "PortRange" in e else {"From": 0, "To": 0}
                out.append(f'  {kind} {{\n    rule_no    = {e["RuleNumber"]}\n    action     = {q(e["RuleAction"])}\n    protocol   = {q(e["Protocol"])}\n'
                           f'    cidr_block = {q(e.get("CidrBlock", "0.0.0.0/0"))}\n    from_port  = {pr.get("From", 0)}\n    to_port    = {pr.get("To", 0)}\n  }}\n')
            return "".join(out)
        sub = [self.names.get(x["SubnetId"], q(x["SubnetId"])) for x in a["Associations"]]
        sub_hcl = "[" + ", ".join(f"{s}.id" if s.startswith("aws_") else s for s in sub) + "]"
        return (f'resource "aws_network_acl" "{n}" {{\n  vpc_id     = {self.names[a["VpcId"]]}.id\n  subnet_ids = {sub_hcl}\n\n'
                f'{entry("ingress", False)}{entry("egress", True)}{hcl_tags(tags(a))}}}\n')

    def instance_block(self, i) -> str:
        n = snake(tags(i).get("Name") or i["InstanceId"])
        self.reg(i["InstanceId"], "aws_instance", n, "ec2.tf")
        root = next(b for b in i["BlockDeviceMappings"] if b["DeviceName"] == i["RootDeviceName"])
        vol = self.ec2.describe_volumes(VolumeIds=[root["Ebs"]["VolumeId"]])["Volumes"][0]
        self.map[vol["VolumeId"]] = {"address": f"aws_instance.{n}", "file": "ec2.tf", "note": "root_block_device"}
        sgs = ", ".join(f"{self.names.get(g['GroupId'], q(g['GroupId']))}.id" if g["GroupId"] in self.names else q(g["GroupId"]) for g in i["SecurityGroups"])
        md = i.get("MetadataOptions", {})
        return (f'resource "aws_instance" "{n}" {{\n  ami                    = {q(i["ImageId"])}\n  instance_type          = {q(i["InstanceType"])}\n'
                f'  subnet_id              = {self.names[i["SubnetId"]]}.id\n  vpc_security_group_ids = [{sgs}]\n\n'
                f'  metadata_options {{\n    http_tokens   = {q(md.get("HttpTokens", "optional"))}\n    http_endpoint = {q(md.get("HttpEndpoint", "enabled"))}\n  }}\n\n'
                f'  root_block_device {{\n    volume_size = {vol["Size"]}\n    volume_type = {q(vol["VolumeType"])}\n    encrypted   = {str(vol["Encrypted"]).lower()}\n  }}\n\n'
                f'{hcl_tags(tags(i))}\n  lifecycle {{\n    ignore_changes = [ami, user_data, user_data_base64]\n  }}\n}}\n')

    def s3_buckets(self):
        for b in self.s3.list_buckets()["Buckets"]:
            name = b["Name"]
            if not S3_SCOPE.match(name):
                continue
            if (self.s3.get_bucket_location(Bucket=name)["LocationConstraint"] or "us-east-1") != self.s.region_name:
                continue  # buckets are global in list_buckets; a regional provider can only manage its own
            n = snake(name)
            self.reg(name, "aws_s3_bucket", n, "s3.tf")
            try:
                bt = {t["Key"]: t["Value"] for t in self.s3.get_bucket_tagging(Bucket=name)["TagSet"] if not t["Key"].startswith("aws:")}
            except self.s3.exceptions.ClientError:
                bt = {}
            self.add("s3.tf", f'resource "aws_s3_bucket" "{n}" {{\n  bucket        = {q(name)}\n  force_destroy = false\n{hcl_tags(bt)}}}\n')
            try:
                p = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                addr = self.reg(name + "#pab", "aws_s3_bucket_public_access_block", n, "s3.tf", name)
                self.add("s3.tf", f'resource "aws_s3_bucket_public_access_block" "{n}" {{\n  bucket                  = aws_s3_bucket.{n}.id\n'
                                  f'  block_public_acls       = {str(p["BlockPublicAcls"]).lower()}\n  block_public_policy     = {str(p["BlockPublicPolicy"]).lower()}\n'
                                  f'  ignore_public_acls      = {str(p["IgnorePublicAcls"]).lower()}\n  restrict_public_buckets = {str(p["RestrictPublicBuckets"]).lower()}\n}}\n')
            except self.s3.exceptions.ClientError:
                pass  # no public access block configured: nothing to mirror (the gap Warden flags)


def generate(out_dir: Path, profile: str | None, region: str = "us-east-1") -> dict:
    g = Gen(profile, region).run()
    out_dir.mkdir(parents=True, exist_ok=True)
    for f, text in g.files.items():
        (out_dir / f).write_text(text)
    (out_dir / "warden-map.json").write_text(json.dumps(g.map, indent=2, sort_keys=True))
    return {"files": sorted(g.files), "resources": len(g.imports), "mapped_ids": len(g.map)}
