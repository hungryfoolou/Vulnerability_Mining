#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取securesoftware的信息
'''

'''
 cve的ref里很少有securesoftware，但触发方法表格里却有许多，比如
 表格里CVE-2004-1287：http://securesoftware.list.cr.yp.to/archive/0/26
 但CVE官网中CVE-2004-1287的ref中并没有http://securesoftware.list.cr.yp.to/archive/0/26
'''

# 爬取securesoftware的title
def craw_title_securesoftware(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write

    title_section = 'securesoftware'  # securesoftware网页中没有具体的title内容
    if len(title_section) > 0:
        dict_to_write[cve_id]['secureSoftware'][link] = {}  # 要初始化，由于先执行craw_title_securesoftware函数，所以在该处初始化
        dict_to_write[cve_id]['secureSoftware'][link]['title'] = title_section
    else:
        print('securesoftware error ' + link)
    return dict_to_write



# 爬取securesoftware的content
def craw_content_securesoftware(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    page = get_page(link)
    cotent_section = str(page.content)
    if len(cotent_section) > 0:
        if cotent_section.find('Content-Type: text/plain; charset=us-ascii') != -1:
            start_pos = cotent_section.find('Content-Type: text/plain; charset=us-ascii') + 75
            cotent_section = cotent_section[start_pos:]
            # cotent_section = cotent_section.replace('\n', ' ').replace('\\r\\n', ' ')
            cotent_section = cotent_section.strip()
            dict_to_write[cve_id]['secureSoftware'][link]['content'] = cotent_section
    else:
        print('securesoftware error ' + link)



# 爬取securesoftware的多种信息
def craw_report_securesoftware(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取securesoftware的title
    dict_to_write = craw_title_securesoftware(cve_id, link, dict_to_write, tree)

    # 获取securesoftware的content
    dict_to_write = craw_content_securesoftware(cve_id, link, dict_to_write, tree)

    return dict_to_write