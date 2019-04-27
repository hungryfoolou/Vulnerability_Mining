#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取marcinfo的信息
'''


# 获取marcinfo的title
def craw_title_marcinfo(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    title_section = tree.xpath('string(/html/body/pre)')
    if len(title_section) > 0:
        dict_to_write[cve_id]['marcInfo'][link] = {}  # 要初始化，由于先执行craw_title_edb函数，所以在该处初始化
        if title_section.find('Subject:') != -1:
            start_pos = title_section.find('Subject:') + 9
            if title_section.find('From:') != -1:
                end_pos = title_section.find('From:')
                title_section = title_section[start_pos:end_pos]
                title0 = title_section.replace('\n', ' ')
                title1 = title0.strip()
                dict_to_write[cve_id]['marcInfo'][link]['title'] = title1
    else:
        print('marcinfo error ' + link)
    return dict_to_write

# 获取marcinfo的content
def craw_content_marcinfo(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    cotent_section = tree.xpath('string(/html/body/pre)')
    if len(cotent_section) > 0:
        if cotent_section.find('Download RAW message or body') != -1:
            start_pos = cotent_section.find('Download RAW message or body') + 30
            end_pos = cotent_section[60:].find('[prev in list]')  # 找结束标志，但是网页前面也有[prev in list]，所以从第60个字符开始找
            cotent_section = cotent_section[start_pos:end_pos+60]  # 与上一行代码对应，也+60
            # cotent_section = cotent_section.replace('\n', ' ')
            cotent_section = cotent_section.strip()
            dict_to_write[cve_id]['marcInfo'][link]['content'] = cotent_section
    else:
        print('marcinfo error ' + link)
    return dict_to_write



# 爬取marcinfo的多种信息
def craw_report_marcinfo(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    try:

        page = get_page(link)  # shadowsocks开全局模式，而PAC模式无法科学上网
        print(link)
        tree = html.fromstring(page.content)
    except Exception as e:
        print(e)

    # 获取marcinfo的title
    dict_to_write = craw_title_marcinfo(cve_id, link, dict_to_write, tree)

    # 获取marcinfo的content
    dict_to_write = craw_content_marcinfo(cve_id, link, dict_to_write, tree)

    return dict_to_write