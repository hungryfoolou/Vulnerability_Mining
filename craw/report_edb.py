#!/usr/bin/env python3
#coding: utf-8


from lxml import html
from getData import get_page
'''
功能：爬取edb的信息
'''


# 爬取edb的title
def craw_title_edb(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    title_section = tree.xpath('/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[1]/h1/text()')
    if len(title_section) > 0:
        dict_to_write[cve_id]['edb'][link] = {}  # 要初始化，由于先执行craw_title_edb函数，所以在该处初始化
        title0 = title_section[0].replace('\n', ' ')
        title1 = str(title0.encode('utf-8'))
        title2 = title1.strip("b' ")
        title3 = title2.strip("'")
        title4 = title3.strip()
        dict_to_write[cve_id]['edb'][link]['title'] = title4
    else:
        print('edb error ' + link)
    return dict_to_write

# 爬取edb的content
def craw_content_edb(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    raw_link = link.replace('/exploits/', '/raw/')
    page = get_page(raw_link)
    content_section = str(page.content).replace('\r\n', ' ').replace('\\r\\n', ' ')
    if len(content_section) > 0:
        dict_to_write[cve_id]['edb'][link]['content'] = content_section
    else:
        print('edb error ' + link)
    return dict_to_write



# 爬取edb的platform
def craw_platform_edb(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    platform_section = tree.xpath('/html/body/div[1]/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[1]/div/div/div/div[1]/h6/a/text()')
    if len(platform_section) > 0:
        try:
            platform_section = platform_section[0].replace('\n', ' ')  # list没有replace操作，list[0]有
            platform1 = str(platform_section.encode('utf-8'))  # 转化为str才能进行后续操作
            platform2 = platform1.strip("b' ")
            platform3 = platform2.strip("'")
            platform4 = platform3.strip()
            dict_to_write[cve_id]['edb'][link]['platform'] = platform4
        except Exception as e:
            print(e)
    else:
        print('edb error ' + link)
    return dict_to_write


# 爬取edb的多种信息
def craw_report_edb(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取edb的title
    dict_to_write = craw_title_edb(cve_id, link, dict_to_write, tree)

    # 获取edb的content
    dict_to_write = craw_content_edb(cve_id, link, dict_to_write, tree)


    return dict_to_write
