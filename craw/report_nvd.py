#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取nvd的信息
'''


# 爬取nvd的title
def craw_title_nvd(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    try:
        # F12得到的源码与实际源代码（右击网页->查看网页源代码），F12得到的xpath路径可能有误。
        title_section = tree.xpath("""string(//*[@id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView"]/tr/td/h2)""")
        # title_section = tree.cssselect('#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView > tbody >tr > td > h2')
    except Exception as e:
        print(e)
    if len(title_section) > 0:
        dict_to_write[cve_id]['nvd'][link] = {}  # 要初始化，由于先执行craw_title_nvd函数，所以在该处初始化
        title1 = title_section.strip()
        dict_to_write[cve_id]['nvd'][link]['title'] = title1
    else:
        print('nvd error ' + link)
    return dict_to_write


# 爬取nvd的content
def craw_content_nvd(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    try:
        # 根据真正的源代码构造xpath
        content_section = tree.xpath("""string(//*[@id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView"]/tr/td/div/div[1]/p[1])""")
        # content_section = tree.cssselect('#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView > tbody >tr > td > h2')
    except Exception as e:
        print(e)
    if len(content_section) > 0:
        content_section = content_section.strip()
        dict_to_write[cve_id]['nvd'][link]['content'] = content_section
    else:
        print('nvd error ' + link)
    return dict_to_write


# 爬取nvd的多种信息
def craw_report_nvd(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取edb的title
    dict_to_write = craw_title_nvd(cve_id, link, dict_to_write, tree)

    # 获取edb的content
    dict_to_write = craw_content_nvd(cve_id, link, dict_to_write, tree)

    return dict_to_write