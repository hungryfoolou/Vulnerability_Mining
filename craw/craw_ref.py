#!/usr/bin/env python3
#coding: utf-8

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup
from os import listdir
from getData import get_pagecontent
'''
功能：获得cve_id的参考链接
'''


def craw_reference():
    cveid_path = 'cve_id/'  # 存放cve_id的文件夹
    cveid_files = listdir(cveid_path)  # cve_id文件夹下的文件
    cveref_path = 'cve_ref/'  # 存放cve_ref的文件夹

    for cveid_file in cveid_files:  # 遍历每个cve_id文件
        cveref_fw = open(cveref_path + cveid_file.replace('_id', '_ref'), 'w')  # 存放cve_ref
        cveid_fr = open(cveid_path + cveid_file, 'r')
        cveid_lines = cveid_fr.readlines()

        for cveid_line in cveid_lines:
            cveref_fw.write('\n' + cveid_line)  # 存储cveid到cve_ref文件中
            cveid = cveid_line
            print('\n' + cveid)

            try:
                link = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveid  # 通过cve官网查询cveid的ref
                page_content = get_pagecontent(link)
                split_lines = page_content.split('\n')
                for line_l in split_lines:
                    loc = line_l.find(':http')  # 每个ref都包括字符串:http
                    if loc != -1:
                        url = line_l[loc + 1:]
                        print(url)
                        cveref_fw.write(url.strip() + '\n')  # 存储ref到cve_ref文件中

            except requests.exceptions.HTTPError as errh:
                print("Http Error: " + str(errh) + " Please check: " + link)
            except requests.exceptions.ConnectionError as errc:
                print("Error Connecting:" + str(errc) + " Please check: " + link)

            except requests.exceptions.Timeout as errt:
                print("Timeout Error:" + str(errt) + " Please check: " + link)
            except requests.exceptions.RequestException as err:
                print("Other errors!" + str(err) + " Please check: " + link)

    return 1
