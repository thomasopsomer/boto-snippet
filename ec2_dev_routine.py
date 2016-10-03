# -*- coding: utf-8 -*-
# @Author: thomasopsomer
from boto3 import Session
import requests
import os
import begin


def get_my_ip():
    url = "http://checkip.amazonaws.com/"
    r = requests.get(url)
    return r.content[:-1]


def get_security_group(ec2, name):
    """
    """
    groups = list(ec2.security_groups.filter(Filters=[{'Name': 'group-name',
                                                       'Values': [name]}
                                                      ]))
    if len(groups) > 0:
        return groups[0]
    else:
        raise ValueError("Security Group: %s not found" % name)


def add_ip_to_security_group(security_group, ip="0.0.0.0/0"):
    """ """
    # authorize http
    security_group.authorize_ingress(
        IpProtocol='tcp',
        FromPort=0,
        ToPort=65535,
        CidrIp=ip)


def remove_ip_to_security_group(security_group, ip="0.0.0.0/0"):
    """ """
    # remove http
    security_group.revoke_ingress(
        IpProtocol='tcp',
        FromPort=0,
        ToPort=65535,
        CidrIp=ip)


@begin.start
def main(sg_name="asgard.ai", action="add", ip=None):
    """ """
    # parse args
    assert action in ["add", "remove"]

    # get aws credential from env
    aws_region = os.environ.get("AWS_REGION", "eu-west-1")
    aws_access_key_id = os.environ["AWS_ACCESS_KEY_ID"]
    aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]

    # aws client
    session = Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region
    )
    ec2 = session.resource('ec2')

    # my ip & security group
    my_ip = get_my_ip() + '/32'
    sg = get_security_group(ec2, name=sg_name)

    already_authorized_ip = list(
        set([x["CidrIp"] for y in sg.ip_permissions for x in y["IpRanges"]])
    )
    # add or remove my ip form security group
    if action == "add" and my_ip not in already_authorized_ip:
        add_ip_to_security_group(sg, my_ip)
        if ip is not None:
            add_ip_to_security_group(sg, ip + "/32")
    elif action == "remove" and my_ip in already_authorized_ip:
        remove_ip_to_security_group(sg, my_ip)
        if ip is not None:
            remove_ip_to_security_group(sg, ip + "/32")


