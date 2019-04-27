#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取sourceware的信息
'''


# 爬取sourceware的title
def craw_title_sourceware(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    title_section = tree.xpath('string(//*[@id="short_desc_nonedit_display"])')
    if len(title_section) > 0:
        try:
            dict_to_write[cve_id]['sourceWare'][link] = {}  # 要初始化，由于先执行函数craw_report_sourceware中的craw_title_sourceware函数，所以在该处初始化
            title0 = title_section.replace('\n', ' ')
            title1 = str(title0.encode('utf-8'))
            title2 = title1.strip("b' ")
            title3 = title2.strip("'")
            title4 = title3.strip()
            dict_to_write[cve_id]['sourceWare'][link]['title'] = title4
        except Exception as e:
            print(e)
    else:
        print('sourceWare error ' + link)
    return dict_to_write


# 爬取sourceware的content
def craw_content_sourceware(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    content_section = tree.xpath('string(//*[@id="c0"]/pre)')
    if len(content_section) > 0:
        try:
            # content_section = content_section.replace('\n', ' ')
            content_section1 = str(content_section.encode('utf-8'))
            content_section2 = content_section1.strip("b' ")
            content_section3 = content_section2.strip("'")
            content_section4 = content_section3.strip()
            dict_to_write[cve_id]['sourceWare'][link]['content'] = content_section4
        except Exception as e:
            print(e)
    else:
        print('sourceWare error ' + link)
    return dict_to_write


# 爬取sourceware的多种信息
def craw_report_sourceware(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取sourceware的title
    dict_to_write = craw_title_sourceware(cve_id, link, dict_to_write, tree)

    # 获取sourceware的content
    dict_to_write = craw_content_sourceware(cve_id, link, dict_to_write, tree)

    return dict_to_write