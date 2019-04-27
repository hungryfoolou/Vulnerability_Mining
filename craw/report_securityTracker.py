#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
from getData import get_pagecontent
'''
功能：爬取securitytracker的信息
'''


# 爬取securitytracker的title，最后一个参数为page
def craw_title_securitytracker(cve_id, link, dict_to_write, page):
    dict_to_write = dict_to_write
    # 也可通过xpath获取title
    # tree = html.fromstring(page.content)
    # title_section = tree.xpath('/html/body/a/table[3]/tr/td[4]/table[3]/tr[1]/td/font/b/text()')

    content = str(page.content)
    keyword_section = content[
                      content.find('<title>') + 7: content.find('</title>') - 18].replace(
        '\n', ' ')
    if len(keyword_section) > 0:
        try:
            dict_to_write[cve_id]['securityTracker'][link] = {}
            dict_to_write[cve_id]['securityTracker'][link]['title'] = str(
                keyword_section.encode('utf-8')).strip("b' ").strip("'").strip()
        except Exception as e:
            print(e)

    else:
        print('securitytracker title error ' + link)
    return dict_to_write


# 爬取securitytracker的content，最后一个参数为page
def craw_content_securitytracker(cve_id, link, dict_to_write, page):
    dict_to_write = dict_to_write

    str_content = get_pagecontent(link)
    start_loc = str_content.find('Description:')+12
    end_loc = str_content.find('Message History:')

    if start_loc < end_loc and start_loc != -1 and end_loc != -1:
        str_content = str_content[start_loc:end_loc]
    if len(str_content) > 0:
        dict_to_write[cve_id]['securityTracker'][link]['content'] = str_content
    else:
        print('securitytracker error ' + link)
    return dict_to_write


# 爬取securitytracker的多种信息
def craw_report_securitytracker(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)

    # 获取securesoftware的title
    dict_to_write = craw_title_securitytracker(cve_id, link, dict_to_write, page)

    # 获取securesoftware的content
    dict_to_write = craw_content_securitytracker(cve_id, link, dict_to_write, page)

    return dict_to_write