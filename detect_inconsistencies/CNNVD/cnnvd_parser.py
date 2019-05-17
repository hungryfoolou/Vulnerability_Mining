#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：获取CNNVD数据
"""

import os
import pymysql
import ast


# 获取cnnvd的CVE和affect_software属性的值
def get_origin_cnnvd():
    try:
        cnnvd_dict = dict()  # 初始化
        # 连接数据库
        # host不写ip地址，否则会报错
        conn = pymysql.connect(host='localhost', port=3306, user='root', passwd='oglhao123', db='cnnvd')  # db：库名
        # 设置游标类型，默认游标类型为元祖形式，将游标类型设置为字典形式
        cur = conn.cursor(cursor=pymysql.cursors.DictCursor)
        cur.execute("select CVE,affect_software from cnnvd where affect_software is not null")
        cnnvd_data = cur.fetchall()
        # cnnvd_data = cur.fetchmany(3) 测试3条数据
        for i in cnnvd_data:
            cnnvd_dict[i['CVE']] = i['affect_software']
            # print(i)

        # 提交
        conn.commit()
        # 关闭指针对象
        cur.close()
        # 关闭连接对象
        conn.close()

        # 保存在本地
        cnnvd_data_path = os.getcwd() + '/data/cnnvd/'  # 存放cvnvd的文件夹
        cnnvd_data_filename = 'cnnvd_' + 'origin.txt'
        cnnvd_data_file_path = os.path.join('%s\%s' % (cnnvd_data_path, cnnvd_data_filename))
        with open(cnnvd_data_file_path, 'w', encoding='utf-8') as cvnvd_data_f:  # 用w而非a，用于覆盖
            cvnvd_data_f.write('cnnvd_dict=' + str(cnnvd_dict))  # 写入数据
    except Exception as e:
        print(e)


# 按照冒号个数分隔affect_software属性的值，以便观察规则分隔出软件名和版本
def split_cnnvd_by_colon():
    cnnvd_data_path = os.getcwd() + '/data/cnnvd/'  # 存放cvnvd的文件夹
    colon_cnnvd_path = os.getcwd() + '/data/cnnvd/split_cnnvd_by_colon'  # 存放split_cnnvd_by_colon的文件夹
    cnnvd_data_filename = 'cnnvd_' + 'origin.txt'
    one_colon_filename = 'cnnvd_' + 'one_colon.txt'
    one_colon_file_path = os.path.join('%s\%s' % (colon_cnnvd_path, one_colon_filename))
    two_colon_filename = 'cnnvd_' + 'two_colon.txt'
    two_colon_file_path = os.path.join('%s\%s' % (colon_cnnvd_path, two_colon_filename))
    three_colon_filename = 'cnnvd_' + 'three_colon.txt'
    three_colon_file_path = os.path.join('%s\%s' % (colon_cnnvd_path, three_colon_filename))
    four_colon_filename = 'cnnvd_' + 'four_colon.txt'
    four_colon_file_path = os.path.join('%s\%s' % (colon_cnnvd_path, four_colon_filename))
    five_colon_filename = 'cnnvd_' + 'five_colon.txt'
    five_colon_file_path = os.path.join('%s\%s' % (colon_cnnvd_path, five_colon_filename))

    cnnvd_data_file_path = os.path.join('%s\%s' % (cnnvd_data_path, cnnvd_data_filename))
    with open(cnnvd_data_file_path, 'r', encoding='UTF-8') as cnnvd_f:  # 打开文件
        cnnvd_lines = cnnvd_f.readlines()  # 获取文件的所有行
        for cnnvd_line in cnnvd_lines:
            cnnvd_data_raw = cnnvd_line
            cnnvd_data_raw = cnnvd_data_raw.lstrip('cnnvd_dict=')
            cnnvd_data_dict = ast.literal_eval(cnnvd_data_raw)  # 转化为字典，只有一行数据，可以不加break
            for i in cnnvd_data_dict:
                cnt = 0
                for j in cnnvd_data_dict[i]:
                    if j == ';':  # 若一个CVEID包括多个软件版本对，则只保留第一个软件版本对
                        break
                    elif j == ':':
                        cnt = cnt + 1
                if cnt == 1:
                    print(i + ' ' + cnnvd_data_dict[i] + '\n')
                    with open(one_colon_file_path, 'a') as one_colon_write:  # 用a而非w，用于追加
                        one_colon_write.write(i + ' ' + cnnvd_data_dict[i] + '\n')
                if cnt == 2:
                    print(i + ' ' + cnnvd_data_dict[i] + '\n')
                    with open(two_colon_file_path, 'a') as two_colon_write:  # 用a而非w，用于追加
                        two_colon_write.write(i + ' ' + cnnvd_data_dict[i] + '\n')
                if cnt == 3:
                    print(i + ' ' + cnnvd_data_dict[i] + '\n')
                    with open(three_colon_file_path, 'a') as three_colon_write:  # 用a而非w，用于追加
                        three_colon_write.write(i + ' ' + cnnvd_data_dict[i] + '\n')
                if cnt == 4:
                    print(i + ' ' + cnnvd_data_dict[i] + '\n')
                    with open(four_colon_file_path, 'a') as four_colon_write:  # 用a而非w，用于追加
                        four_colon_write.write(i + ' ' + cnnvd_data_dict[i] + '\n')
                # 运行后发现没有cnt>=5的


def get_softname_and_version_of_cnnvd():
    cnnvd_data_path = os.getcwd() + '/data/cnnvd/'  # 存放cvnvd的文件夹
    cnnvd_data_filename = 'cnnvd_' + 'origin.txt'
    name_and_version_filename = 'cnnvd_' + 'softname_and_version.txt'
    print_name_and_version_filename = 'cnnvd_' + 'softname_and_version_print.txt'
    cnnvd_data_file_path = os.path.join('%s\%s' % (cnnvd_data_path, cnnvd_data_filename))
    name_and_version_file_path = os.path.join('%s\%s' % (cnnvd_data_path, name_and_version_filename))
    print_name_and_version_file_path = os.path.join('%s\%s' % (cnnvd_data_path, print_name_and_version_filename))
    name_and_version_dict = dict()  # 初始化
    with open(cnnvd_data_file_path, 'r', encoding='UTF-8') as cnnvd_f:  # 打开文件
        cnnvd_lines = cnnvd_f.readlines()  # 获取文件的所有行
        for cnnvd_line in cnnvd_lines:
            cnnvd_data_raw = cnnvd_line
            cnnvd_data_raw = cnnvd_data_raw.lstrip('cnnvd_dict=')
            cnnvd_data_dict = ast.literal_eval(cnnvd_data_raw)  # 转化为字典，只有一行数据，可以不加break
            for i in cnnvd_data_dict:
                soft_parts = cnnvd_data_dict[i].split(';')
                for j in soft_parts:
                    parts = j.split(':')  # 用冒号分隔，第一个冒号前的为软件名，后面都为版本
                    part_cnt = 0
                    name = ''
                    version = ''
                    for part in parts:
                        part_cnt = part_cnt + 1
                        part = part.strip().replace('_', ' ').replace('~', ' ')  # 能够过滤掉符号_前有空格的情况
                        if part_cnt == 1:
                            name = part
                        elif part == '-':
                            continue
                        else:
                            if version == '':
                                version = part
                            else:
                                version = version + ' ' + part
                    if (i.split() != '') and (i not in name_and_version_dict):
                        name_and_version_dict[i] = {}
                    if (name.split() != '') and (name not in name_and_version_dict[i]):
                        name_and_version_dict[i][name] = []
                    if (version.split() != '') and (version not in name_and_version_dict[i][name]):  # version不能为''
                        name_and_version_dict[i][name].append(version)
    # 保存在本地
    with open(name_and_version_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(name_and_version_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in name_and_version_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(name_and_version_dict[j]) + '\n')  # 写入数据

