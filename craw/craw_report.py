#!/usr/bin/env python3
#coding: utf-8

from os import listdir
from lxml import html
import requests

from report_bugsGentoo import craw_report_bugsgentoo
from report_edb import craw_report_edb
from report_marcInfo import craw_report_marcinfo
from report_nvd import craw_report_nvd
from report_seclists import craw_report_seclists
from report_secureSoftware import craw_report_securesoftware
from report_securityFocus import craw_report_securityfocus_general
from report_securityFocus import craw_report_securityfocus_official
from report_securityTracker import craw_report_securitytracker
from report_sourceWare import craw_report_sourceware
from getData import get_page

'''
功能：爬取报告
'''

def craw_report():
    ref_path = 'cve_ref/'  # 存放cve_ref的文件夹
    report_path = 'report/'  # 存放report的文件夹
    ref_files = listdir(ref_path)  # cve_ref文件夹下的文件

    for ref_file in ref_files:  # 遍历所有cve_ref文件
        dict_to_write = {}   # 存放report的所有信息,不应该放在上面for循环的外面，如果放在外面的话dict_to_write就相当于把前一个文件的信息继续保持在后面的文件中了
        with open(ref_path + ref_file, 'r') as ref_fr:
            ref_lines = ref_fr.read().split('\n\n')
            with open(report_path + ref_file.replace('cve_ref', 'report'), 'w') as f_csv:  # 存放report
                for ref_line in ref_lines:
                    try:
                        cve_refs_list = ref_line.strip('\n').split('\n')
                        cve_id = cve_refs_list[0][cve_refs_list[0].find('\t') + 1:]

                        '''
                        为每个cve_id(键)存储相关的cve官网和其他ref网站的信息(值)，值也是字典构成的，
                        值的字典中的键为link，link对应的值为content、title等。                       
                        '''
                        dict_to_write[cve_id] = {'cve': {}, 'edb': {}, 'bugsGentoo': {}, 'marcInfo': {}, 'nvd':{}, 'seclists':{}, 'secureSoftware':{}, 'securityFocus': {}, 'securityFocusOfficial': {}, 'securityTracker': {},
                                                 'sourceWare': {}}
                        print(ref_file, cve_id)

                        link = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve_id
                        page = get_page(link)
                        tree = html.fromstring(page.content)

                        # 保存cve官网页面的Description版块的内容
                        keyword_section = tree.xpath('string(//*[@id="GeneratedTable"]/table/tr[4]/td)')  # 更改表达式，下面的keyword_section[0]去掉[0]，比如https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0020有REJECT a标签的情况

                        if len(keyword_section) > 0:
                            keyword_section = keyword_section.replace('\n', ' ').strip()
                            dict_to_write[cve_id]['cve'][link] = {}
                            dict_to_write[cve_id]['cve'][link]['content'] = keyword_section
                        else:
                            print('cve error ' + link)
                        for link in cve_refs_list[1:]:  # 对每个cve_id，遍历它的所有的ref网页，保存ref的title等内容
                            status_code = requests.get(link, allow_redirects=False).status_code
                            if status_code == 403 or status_code == 404:  # 过滤404和403网页，注意if语法，if a ==403 or a==404
                                continue
                            pos_http = link.find('http')
                            if link[pos_http+4] != ':':  # 过滤包含http但并不是网址的字符串，比如:http-cgi-nlog-netbios(1550)
                                continue
                            if link.find('bugs.gentoo') != -1:
                                dict_to_write = craw_report_bugsgentoo(cve_id, link, dict_to_write)
                            elif link.find('exploit-db.com') != -1:
                                #  过滤网页：http://www.exploit-db.com/exploits/36039(这是一个404的网页)
                                if link != 'http://www.exploit-db.com/exploits/36039':
                                    dict_to_write = craw_report_edb(cve_id, link, dict_to_write)
                            elif link.find('marc.info') != -1:
                                dict_to_write = craw_report_marcinfo(cve_id, link, dict_to_write)
                            elif link.find('nvd.nist.gov') != -1:
                                dict_to_write = craw_report_nvd(cve_id, link, dict_to_write)
                            elif link.find('seclists') != -1:
                                dict_to_write = craw_report_seclists(cve_id, link, dict_to_write)
                            elif link.find('securesoftware') != -1:
                                dict_to_write = craw_report_securesoftware(cve_id, link, dict_to_write)
                            elif link.find('securityfocus.com/bid') != -1:   # 有两个securityfocus网站
                                dict_to_write = craw_report_securityfocus_official(cve_id, link, dict_to_write)
                            elif link.find('www.securityfocus.com/archiv') != -1:
                                #  过滤网页：http://www.securityfocus.com/bid/215 This reference(这是一个奇怪的网页)
                                if link.find('This reference') == -1:
                                    dict_to_write = craw_report_securityfocus_general(cve_id, link, dict_to_write)
                            elif link.find('www.securitytracker.com/id') != -1:
                                dict_to_write = craw_report_securitytracker(cve_id, link, dict_to_write)
                            elif link.find('sourceware.org/bugzilla/show_bug.cgi') != -1:
                                dict_to_write = craw_report_sourceware(cve_id, link, dict_to_write)

                    except requests.exceptions.HTTPError as errh:
                        print("Http Error: " + str(errh) + " Please check: " + link)
                    except requests.exceptions.ConnectionError as errc:
                        print("Error Connecting:" + str(errc) + " Please check: " + link)
                    except requests.exceptions.Timeout as errt:
                        print("Timeout Error:" + str(errt) + " Please check: " + link)
                    except requests.exceptions.RequestException as err:
                        print("Other errors!" + str(err) + " Please check: " + link)
                f_csv.write('dict_to_write = ' + str(dict_to_write))



