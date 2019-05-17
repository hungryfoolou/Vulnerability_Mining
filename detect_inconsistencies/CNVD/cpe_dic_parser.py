#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：解析CPE里的软件名称和版本
"""

import os
from xml.dom import minidom
import program_config
import program_utils
from get_data import get_software_name_and_version_from_cpe


# 字典的键为软件名称（厂商名+产品名），值为一个list，list里面为软件版本，list比如为['2.7.0','2.7.1']
def parse_cpe_xml():
    software_version_dict = dict()
    cpe_dic_path = os.getcwd() + '/data/cpe-dictionary/'  # 存放cpe字典的文件夹
    cpe_dic_filename = 'official-cpe-dictionary_v2.3.xml'
    cpe_dic_name = os.path.join('%s\%s' % (cpe_dic_path, cpe_dic_filename))
    xmldoc = minidom.parse(cpe_dic_name)
    itemlist = xmldoc.getElementsByTagName('cpe-23:cpe23-item')
    # print(len(itemlist))
    # print(itemlist[0].attributes['name'].value)
    # print(commons.excel_data_path.replace('_a', ''))

    for s in itemlist:
        cpe = s.attributes['name'].value  # 调试发现'name'在s的属性'_attrs'下
        software, version = get_software_name_and_version_from_cpe(cpe)  # 厂商名作为了软件名的一部分，nvd_json_dict软件名也这样
        software = clean_software_name(software)
        if software.startswith('a '):
            print(software)
        if (software != '') and (software not in software_version_dict):  # 修改师姐代码，不保留为''的键
            software_version_dict[software] = []
        if (software != '') and (version != ''):  # 相应地这里也要改
            software_version_dict[software].append(version)
    print('len(software_version_dict): ', len(software_version_dict))
    write_software_name_version_dict(software_version_dict)


def write_software_name_version_dict(software_version_dict):
    for software in software_version_dict:
        software_version_dict[software] = sorted(software_version_dict[software])  # 排序，sort()与sorted()不同
    cpe_dic_path = os.getcwd() + '/data/cpe-dictionary/'  # 存放cpe字典的文件夹
    cpe_dic_filename = 'cpe_name_dic.txt'
    cpe_dic_name = os.path.join('%s\%s' % (cpe_dic_path, cpe_dic_filename))
    with open(cpe_dic_name, 'w') as f_write:  # 用w而非a，用于覆盖
        f_write.write('cpe_software_version_dict=' + str(software_version_dict))
    # 为了方便观察，以较好的格式另外保存到一个文件中
    print_name_and_version_filename = 'cpe_name_dic_print.txt'
    print_name_and_version_file_path = os.path.join('%s\%s' % (cpe_dic_path, print_name_and_version_filename))
    for j in software_version_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(software_version_dict[j]) + '\n')  # 写入数据


def clean_software_name(software):
    software_word_list = software.split()
    if software_word_list[0] in ['a', 'h', 'o']:
        software_word_list = software_word_list[1:]
        software = ' '.join(software_word_list)
    if len(software_word_list) > 1 and software_word_list[0] == software_word_list[1]:
        software_word_list = software_word_list[1:]
        software = ' '.join(software_word_list)
    return software


