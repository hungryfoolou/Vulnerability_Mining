#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取securityfocus_general和securityfocus_official的信息
'''

# securityfocus_general的网页没有任何有用信息，可能是之前的链接失效了
# 爬取securityfocus_general的title
def craw_title_securityfocus_general(cve_id, link, dict_to_write, tree):
    return dict_to_write


# 爬取securityfocus_general的content
def craw_content_securityfocus_general(cve_id, link, dict_to_write, tree):
    return dict_to_write


# 爬取securityfocus_general的多种信息
def craw_report_securityfocus_general(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取securityfocus_general的title
    dict_to_write = craw_title_securityfocus_general(cve_id, link, dict_to_write, tree)

    # 获取securityfocus_general的content
    dict_to_write = craw_content_securityfocus_general(cve_id, link, dict_to_write, tree)

    return dict_to_write


# 爬取securityfocus_official的title
def craw_title_securityfocus_official(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    title_section = tree.xpath('string(//*[@id="vulnerability"]/span)')
    if len(title_section) > 0:
        dict_to_write[cve_id]['securityFocusOfficial'][link] = {}  # 要初始化，由于先执行craw_title_securityfocus_official函数，所以在该处初始化
        title0 = title_section.replace('\n', ' ')
        title1 = str(title0.encode('utf-8'))
        title2 = title1.strip("b' ")
        title3 = title2.strip("'")
        title4 = title3.strip()
        dict_to_write[cve_id]['securityFocusOfficial'][link]['title'] = title4
    else:
        print('securityfocus_official error ' + link)
    return dict_to_write


# 爬取securityfocus_official的content
def craw_content_securityfocus_official(cve_id, raw_link, dict_to_write, tree):
    dict_to_write = dict_to_write
    s2r_section = tree.xpath('string(//*[@id="vulnerability"])')

    link = raw_link.replace('/exploit', '')
    tmp_title = dict_to_write[cve_id]['securityFocusOfficial'][link]['title']
    s2r_section = s2r_section.replace(tmp_title, '')  # 由于content无需包括标题部分，所以去除标题部分

    if len(s2r_section) > 0:
        s2r0 = s2r_section.replace('\n', ' ').replace('\t', '')
        s2r1 = str(s2r0.encode('utf-8'))
        s2r2 = s2r1.strip("b' ")
        s2r3 = s2r2.strip("'")
        s2r4 = s2r3.strip()
        dict_to_write[cve_id]['securityFocusOfficial'][link]['content'] = s2r4
    else:
        print('securityfocus_official error ' + link)
    return dict_to_write


# 爬取securityfocus_official的多种信息
def craw_report_securityfocus_official(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write
    if link.find('/exploit') != -1:  # 有的链接本身就加了/exploit
        link = link.strip('/exploit')

    page = get_page(link)

    #  排除页面内容为空的情况，比如：https://www.securityfocus.com/bid/637
    if str(page.content).find('Sorry, the content you are trying to view does not exist') != -1:
        return dict_to_write



    print(link)
    tree = html.fromstring(page.content)

    # 获取securityfocus_official的title
    dict_to_write = craw_title_securityfocus_official(cve_id, link, dict_to_write, tree)

    raw_link = link + '/exploit'
    page = get_page(raw_link)
    print(raw_link)
    tree = html.fromstring(page.content)

    # 获取securityfocus_official的content
    dict_to_write = craw_content_securityfocus_official(cve_id, raw_link, dict_to_write, tree)

    return dict_to_write