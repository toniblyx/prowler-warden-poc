"""Repeatable live demo: a throwaway VPC + security group (tagged warden-demo) that we open to the internet on port 22.
Warden should detect the change from CloudTrail and, in auto mode, close it. Only resources tagged warden-demo are touched."""
import boto3

from . import config

TAG = {"Key": "warden-demo", "Value": "true"}
CIDR = "10.250.0.0/28"


def _ec2():
    return boto3.Session(profile_name=config.PROFILE, region_name=config.REGION).client("ec2")


def _find(ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:warden-demo", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        return None, None
    vid = vpcs[0]["VpcId"]
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vid]}, {"Name": "group-name", "Values": ["warden-demo-bastion"]}])["SecurityGroups"]
    return vid, (sgs[0] if sgs else None)


def status() -> dict:
    ec2 = _ec2()
    vid, sg = _find(ec2)
    open22 = bool(sg) and any(r.get("CidrIp") == "0.0.0.0/0" and p.get("FromPort") == 22
                              for p in sg["IpPermissions"] for r in p.get("IpRanges", []))
    return {"vpc": vid, "sg": sg["GroupId"] if sg else None, "port22_open_to_internet": open22}


def start() -> dict:
    """Create (if needed) the demo VPC + SG and open 22 to 0.0.0.0/0: the change Warden should catch."""
    ec2 = _ec2()
    vid, sg = _find(ec2)
    if not vid:
        vid = ec2.create_vpc(CidrBlock=CIDR, TagSpecifications=[{"ResourceType": "vpc", "Tags": [TAG, {"Key": "Name", "Value": "warden-demo"}]}])["Vpc"]["VpcId"]
    gid = sg["GroupId"] if sg else ec2.create_security_group(
        GroupName="warden-demo-bastion", Description="Warden live demo - safe to delete", VpcId=vid,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [TAG]}])["GroupId"]
    if not status()["port22_open_to_internet"]:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "warden demo"}]}])
    return status()


def reset() -> dict:
    """Delete everything the demo created so it can be run again from scratch."""
    ec2 = _ec2()
    vid, sg = _find(ec2)
    if sg:
        ec2.delete_security_group(GroupId=sg["GroupId"])
    if vid:
        ec2.delete_vpc(VpcId=vid)
    return status()
