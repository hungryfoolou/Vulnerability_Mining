#!/usr/bin/env python3
#coding: utf-8

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup
import os.path
import ast
'''
功能：一些简单的数据处理
'''

CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)
class DESAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)


# 获取页面，通过这种方式获取页面可避免SSL error
def get_page(link):
    # requests.adapters.DEFAULT_RETRIES = 5  # 增加重连次数
    s = requests.Session()
    s.mount(link, DESAdapter())
    # s.keep_alive = False  # 关闭多余连接
    # s.proxies = {"https": "183.195.145.174:5328", "http": "49.51.195.24:1080", }  # 访问次数频繁，被禁止访问，解决方法：使用代理:http://ip.zdaye.com/FreeIPlist.html?ip=&adr=%C9%CF%BA%A3&checktime=&sleep=&cunhuo=&dengji=&nadr=&https=&yys=&post=&px=
    page = s.get(link, timeout=60, headers={'User-Agent': "Magic Browser"})
    return page


# 获取BeautifulSoup的页面
def get_pagecontent(link):
    page = get_page(link)
    page_content = BeautifulSoup(page.content).get_text()
    return page_content

# 把大的cve_ref文件切分成小的cve_ref文件（按照年份），程序没有保留最后一年（2019）的数据（2019年的CVE的ref都是空的，没必要保留）
def get_small_cve_ref():
    file_path = 'cve_ref/'  # 原始数据的目录
    try:
        path_dir = os.listdir(file_path)  # 获取目录下的文件
        for all_dir in path_dir:  # 遍历文件
            child = os.path.join('%s\%s' % (file_path, all_dir))  # 获取文件的完整的路径
            if os.path.isfile(child):
                with open(child,'r',encoding='UTF-8') as f:  # 打开文件
                    lines = f.readlines()  # 获取文件的所有行
                    year = 1999  # 从1999年开始
                    start_line = 0
                    line_cnt = 0  # 文件行数
                    for line in lines:
                        line_cnt = line_cnt + 1
                        if line.find('CVE-'+ str(year+1)) != -1:  # 找到下一年的数据了，接下来保存本年的数据
                            new_lines = lines[start_line:line_cnt-1]
                            new_dir = str(year) + '_' + all_dir
                            new_file_path = os.path.join('%s\%s' % (file_path, new_dir))
                            with open(new_file_path, 'w', encoding='utf-8') as newf:
                                for new_line in new_lines:
                                    newf.write(new_line)
                            start_line = line_cnt-1
                            year = year + 1
                break  # 只遍历一个大的cve_ref文件
    except Exception as ex:
        print(ex)


# 把craw_report.py爬取的report里的信息进行更规则地保存
def split_report_into_files():
    try:
        report_raw_path = 'report/'  # 存放原始report文件夹
        report_raw_files = os.listdir(report_raw_path)  # 原始report文件夹下的文件
        report_detailed_path = 'report_detailed_file/'  # 存放详细report的文件夹

        for report_raw_file in report_raw_files:  # 遍历每个原始report文件
            child = os.path.join('%s\%s' % (report_raw_path, report_raw_file))  # 获取文件的完整的路径
            if os.path.isfile(child):

                # 记录可能包括s2r的CVE编号文件列表
                mays2r_path = report_detailed_path
                mays2r_dir = 's2rinfo_' + report_raw_file + '.txt'
                mays2r_file_path = os.path.join('%s\%s' % (mays2r_path, mays2r_dir))
                with open(mays2r_file_path, 'w', encoding='utf-8') as mays2rf:
                    mays2rf.write('The list cveid not only include official cve info,so it may include other website\'s s2r:\n')

                with open(child, 'r', encoding='UTF-8') as f:  # 打开文件
                    lines = f.readlines()  # 获取文件的所有行
                    for line in lines:
                        report_raw = line
                        report_raw = report_raw.lstrip('dict_to_write = ')
                        raw_dict = ast.literal_eval(report_raw)  # 转化为字典
                        for key1 in raw_dict:
                            print(key1, ':', raw_dict[key1])
                            cveid = key1
                            cvecontent = raw_dict[key1]

                            # 判断cveid是否可能包括s2r
                            mays2r_flag = False

                            if key1 and cvecontent:  # 排除键、值为空的情况
                                os.mkdir(os.path.join(report_detailed_path, cveid))  # 新建文件夹（以CVEID命名）
                                for key2 in cvecontent:
                                    # print(key2, ':', cvecontent[key2])
                                    if cvecontent[key2]:  # 键对应的值（也为字典）不为空
                                        web_index = key2  # cve/edb/bugsGentoo/...
                                        os.mkdir(os.path.join(report_detailed_path, cveid, web_index))  # 新建文件夹（以cve/edb等命名）

                                        # 若ref不只是包括cve，则可能包括其他参考网站的s2r（cve官网页面没有s2r）
                                        if web_index != 'cve':
                                            mays2r_flag = True

                                        web_content = cvecontent[key2]
                                        for key3 in web_content:
                                            detail_link = key3  # 网页具体链接
                                            print(key3, ':', web_content[key3], '\n')

                                            # 写入链接（除了content外，其他信息均存储在basicinfo.txt中）
                                            file_path = os.path.join(report_detailed_path, cveid, web_index)
                                            new_dir = 'basicinfo.txt'
                                            new_file_path = os.path.join('%s\%s' % (file_path, new_dir))
                                            with open(new_file_path, 'w', encoding='utf-8') as newf:
                                                newf.write('link:\n'+detail_link+'\n')

                                            detail_value = web_content[key3]  # 该网页链接对应的具体content
                                            if detail_value:  # 不为空
                                                #  先判断是否存在某个键
                                                if 'title' in detail_value.keys():  # 写入title
                                                    detail_title = detail_value['title']
                                                    with open(new_file_path, 'w', encoding='utf-8') as newf:
                                                        newf.write('title:\n' + detail_title + '\n')
                                                if 'content' in detail_value.keys():  # 写入content
                                                    detail_content = detail_value['content']
                                                    content_dir = 'content.txt'
                                                    new_content_path = os.path.join('%s\%s' % (file_path, content_dir))
                                                    with open(new_content_path, 'w', encoding='utf-8') as newcontentf:
                                                        newcontentf.write(detail_content + '\n')

                            if mays2r_flag == True:  # 可能包括s2r
                                print('The file not just include cve content.may include s2r\n')
                                with open(mays2r_file_path, 'w', encoding='utf-8') as mays2rf:
                                    mays2rf.write(cveid + '\n')  # 记录可能包括S2R的CVEID
    except Exception as e:
        print(e)







