# -*- coding: utf-8 -*-

# https://developer.cisco.com/learning/lab/dnav3-dnac-nbapi-hello-world
import sys
import requests
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

DNAC_HOST = 'sandboxdnac.cisco.com'
DNAC_POST = 443
DNAC_USER = 'devnetuser'
DNAC_PASSWORD = 'Cisco123!'


def get_auth_token(controller_ip=DNAC_HOST, post=DNAC_POST, username=DNAC_USER, password=DNAC_PASSWORD):
    login_url = "https://{0}/dna/system/api/v1/auth/token".format(controller_ip, post)
    # Cisco DNA Center设备上有自签名证书，不是由CA颁发的，所以参数verify置False
    result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
    # 如果请求有任何问题，并且有任何响应代码不同于200 OK，则raise_for_status()将退出脚本并显示一条Traceback消息，指示请求的问题
    result.raise_for_status()

    return result.json()["Token"]


def get_url(path, controller_ip=DNAC_HOST):
    url = "https://%s/dna/intent/api/v1/%s" % (controller_ip, path)
    print(url)
    token = get_auth_token()
    headers = {
        'X-auth-token': token
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()


# 获取由Cisco DNA Center管理的所有网络设备的列表
def list_network_devices():
    return get_url("network-device")


if __name__ == "__main__":
    response = list_network_devices()
    print(
        "{0:42}{1:17}{2:12}{3:18}{4:12}{5:16}{6:15}".format("hostname", "mgmt IP", "serial", "platformId", "SW Version",
                                                            "role", "Uptime"))

    for device in response['response']:
        uptime = "N/A" if device['upTime'] is None else device['upTime']
        print("{0:42}{1:17}{2:12}{3:18}{4:12}{5:16}{6:15}".format(device['hostname'], device['managementIpAddress'],
                                                                  device['serialNumber'], device['platformId'],
                                                                  device['softwareVersion'], device['role'], uptime))
