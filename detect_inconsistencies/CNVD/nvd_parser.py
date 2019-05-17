#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：获取nvd的软件名称和版本
"""

import re
import requests
import zipfile
import io
import json
import os
import ast


# 返回nvd数据，full为True时返回所有年份的数据。每条数据的键为CVEID，值也为字典，值里的键包括ref,cve(CVE官网的description)，nvd，\
# ref的值为该CVEID所有参考链接的列表，cve值为字符串，nvd值也为一个字典，其中键为“厂商名 产品名”，值为版本号
def download_nvd_data(nvd_year_list_to_download, full=True):
    nvd_json_version_dict = dict()
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')

    for filename in re.findall("nvdcve-1.0-[0-9]*\.json\.zip", r.text):  # 找到所有年份的数据
        if not full:
            if extract_year(filename) not in nvd_year_list_to_download:  # 只需要得到某些年份的数据
                continue
        print("Downloading {}".format(filename))
        r_zip_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
        zip_file_bytes = io.BytesIO()

        for chunk in r_zip_file:
            zip_file_bytes.write(chunk)

        zip_file = zipfile.ZipFile(zip_file_bytes)

        for json_filename in zip_file.namelist():
            print("Extracting {}".format(json_filename))
            json_raw = zip_file.read(json_filename).decode('utf-8')
            json_data = json.loads(json_raw)

            for entry in json_data['CVE_Items']:  # 遍历每个文件的每个CVEID对应的数据
                cveid = entry['cve']['CVE_data_meta']['ID']  # 获取CVEID
                nvd_json_version_dict[cveid] = {'ref':[], 'cve':'', 'nvd':{}}  # CVEID为键，值为一个字典

                for ref in entry['cve']['references']['reference_data']:
                    nvd_json_version_dict[cveid]['ref'].append(ref['url'])  #  获取ref的值

                # for description in entry['cve']['description']:
                nvd_json_version_dict[cveid]['cve'] = entry['cve']['description']['description_data'][0]['value']  # 获取CVE官网的description

                for vendor_idx in list(range(len(entry['cve']['affects']['vendor']['vendor_data']))):
                    try:
                        vendor_name = entry['cve']['affects']['vendor']['vendor_data'][vendor_idx]['vendor_name']  # 获取厂商名字
                    except IndexError:
                        vendor_name = ""
                    try:
                        for pd in entry['cve']['affects']['vendor']['vendor_data'][vendor_idx]['product']['product_data']:
                            vv = []
                            pd_name = pd['product_name'].replace('_', ' ')  # 获取产品名字
                            for vd in pd['version']['version_data']:  # 遍历产品的版本信息
                                vv.append([vd['version_affected'].lower(), vd['version_value'].lower()])  # 获取产品版本，version_affected为=或者<=
                            if pd_name != '' and vv != []:
                                # '<='转换为' and earlier'
                                nvd_json_version_dict[cveid]['nvd'][(vendor_name + ' ' + pd_name).lower()] = transform_version(vv)
                    except IndexError:
                        pass
    # 保存在本地
    nvd_data_path = os.getcwd() + '/data/nvd/'  # 存放nvd的文件夹
    nvd_data_filename = 'nvd_' + 'origin.txt'
    nvd_data_file_path = os.path.join('%s\%s' % (nvd_data_path, nvd_data_filename))
    with open(nvd_data_file_path, 'w', encoding='utf-8') as nvd_data_f:  # 用w而非a，用于覆盖
        nvd_data_f.write('nvd_json_version_dict=' + str(nvd_json_version_dict))  # 写入数据
    # return nvd_json_version_dict


def transform_version(version_list):
    new_version_list = []
    for range_point in version_list:
        version_range, point = range_point
        if version_range == '<=':
            # 修改师姐的代码，之前为append(point + ' and earlier')，之前这样写的理由是：因为其它漏洞库都是 and earlier 这种形式，我处理其它漏洞库的时候需要转换形式，想把NVD和其它的漏洞库漏洞报告一起处理了，所以转换了NVD的格式，你不涉及其它漏洞报告，所以可以不用这一步
            new_version_list.append('<=' + point)
        elif version_range == '=':
            new_version_list.append(point)
        else:
            print('ERROR! range is: ', version_range)
    return new_version_list


def extract_year(filename):
    return filename.split('-')[2].split('.')[0]


# 去除nvd的不必要的信息，自保留CVEID、软件名、版本
def get_softname_and_version_of_nvd():
    nvd_data_path = os.getcwd() + '/data/nvd/'  # 存放nvd的文件夹
    nvd_data_filename = 'nvd_' + 'origin.txt'
    nvd_data_file_path = os.path.join('%s\%s' % (nvd_data_path, nvd_data_filename))

    name_and_version_filename = 'nvd_' + 'softname_and_version.txt'
    print_name_and_version_filename = 'nvd_' + 'print_softname_and_version.txt'
    name_and_version_file_path = os.path.join('%s\%s' % (nvd_data_path, name_and_version_filename))
    print_name_and_version_file_path = os.path.join('%s\%s' % (nvd_data_path, print_name_and_version_filename))
    name_and_version_dict = dict()  # 初始化
    with open(nvd_data_file_path, 'r', encoding='UTF-8') as nvd_f:  # 打开文件
        nvd_lines = nvd_f.readlines()  # 获取文件的所有行
        for nvd_line in nvd_lines:
            nvd_data_raw = nvd_line
            nvd_data_raw = nvd_data_raw.lstrip('nvd_json_version_dict=')
            nvd_data_dict = ast.literal_eval(nvd_data_raw)  # 转化为字典，只有一行数据，可以不加break
            for cveid in nvd_data_dict:
                if (cveid.split() != '') and (cveid not in name_and_version_dict):
                    name_and_version_dict[cveid] = {}
                nvd_data = nvd_data_dict[cveid]['nvd']
                for soft in nvd_data:
                    if (soft.split() != '') and (soft not in name_and_version_dict[cveid]):
                        name_and_version_dict[cveid][soft] = []
                    version = nvd_data[soft]
                    name_and_version_dict[cveid][soft] = version  # 与cnvd的get_softname_and_version_of_cnvd处理方式不同，不必使用append()
    # 保存在本地
    with open(name_and_version_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(name_and_version_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in name_and_version_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(name_and_version_dict[j]) + '\n')  # 写入数据
