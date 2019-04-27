#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取bugsGentoo的信息
'''

# 爬取bugsgentoo的title
def craw_title_bugsgentoo(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    title_section = tree.xpath('//*[@id="short_desc_nonedit_display"]/text()')
    if len(title_section) > 0:
        dict_to_write[cve_id]['bugsGentoo'][link] = {}  # 要初始化，由于先执行craw_title_bugsgentoo函数，所以在该处初始化
        title0 = title_section[0].replace('\n', ' ')
        title1 = str(title0.encode('utf-8'))
        title2 = title1.strip("b' ")
        title3 = title2.strip("'")
        title4 = title3.strip()
        dict_to_write[cve_id]['bugsGentoo'][link]['title'] = title4
    else:
        print('edb error ' + link)
    return dict_to_write

# 爬取bugsgentoo的content
def craw_content_bugsgentoo(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write
    title_section = tree.xpath('string(//*[@id="c0"]/pre)')  # 网页的description部分
    if len(title_section) > 0:
        # title_section = title_section.replace('\n', ' ')
        title1 = str(title_section.encode('utf-8'))
        title2 = title1.strip("b' ")
        title3 = title2.strip("'")
        title4 = title3.strip()
        dict_to_write[cve_id]['bugsGentoo'][link]['content'] = title4
    else:
        print('edb error ' + link)
    return dict_to_write

# 爬取bugsgentoo的s2r,该函数考虑得不周全，得爬取所有内容后标记
def craw_s2r_bugsgentoo(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write

    # string()提取标签下的所有文本内容，且s2r为string类型，所以下面不是对s2r_sec[0]进行操作，而是对s2r_sec操作
    s2r_sec = tree.xpath('string(//*[@id="c0"]/pre)')
    if s2r_sec.find('Steps to Reproduce') != -1 or s2r_sec.find('Proof of concept') != -1:
        if s2r_sec.find('Steps to Reproduce') != -1:
            s2r_section = s2r_sec[s2r_sec.find('Steps to Reproduce'):]
        else:
            s2r_section = s2r_sec[s2r_sec.find('Proof of concept'):]

        '''
        观察发现，s2r结束后的下一行的内容通常包含冒号m,
        s2r中通常没有冒号（去掉冒号后有/的情况，比如s2r中可能出现ftp://(详见https://bugs.gentoo.org/74478)）
        '''
        if s2r_section.find(':') != -1:
            front_s2r_section = s2r_section[0:s2r_section.find(':')+2]
            tmp_s2r_section = s2r_section[s2r_section.find(':')+2:]

            start_pos = 0
            while tmp_s2r_section[start_pos:].find(':') != -1:
                tmp_colon = tmp_s2r_section[start_pos:].find(':')
                if tmp_s2r_section[tmp_colon + 1] != '/':  # 找到了冒号m(去掉冒号后有/的情况)
                    tmp_s2r_section = tmp_s2r_section[0:tmp_colon+start_pos]
                    tmp_s2r_section = tmp_s2r_section[::-1]
                    for index, item in enumerate(tmp_s2r_section):
                        if item == '\n':
                            pos_newline = index
                            tmp_s2r_section = tmp_s2r_section[pos_newline + 1:]
                            tmp_s2r_section = tmp_s2r_section[::-1]
                            s2r_section = front_s2r_section + tmp_s2r_section
                            break
                else:
                    start_pos = tmp_colon + 1  # 继续寻找冒号
        dict_to_write[cve_id]['bugsGentoo'][link]['s2r'] = s2r_section  # 保存s2r
    return dict_to_write


# 爬取bugsgentoo的多种信息
def craw_report_bugsgentoo(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取edb的title
    dict_to_write = craw_title_bugsgentoo(cve_id, link, dict_to_write, tree)

    # 获取edb的content
    dict_to_write = craw_content_bugsgentoo(cve_id, link, dict_to_write, tree)

    return dict_to_write