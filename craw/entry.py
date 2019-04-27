#!/usr/bin/env python3
#coding: utf-8

from craw_ref import craw_reference
from craw_report import craw_report
from report_bugsGentoo import craw_report_bugsgentoo
from report_bugsGentoo import craw_title_bugsgentoo
from report_marcInfo import craw_title_marcinfo
from report_marcInfo import craw_report_marcinfo
from report_nvd import craw_title_nvd
from report_nvd import craw_report_nvd
from report_seclists import craw_title_seclists
from report_seclists import craw_report_seclists
from report_secureSoftware import craw_title_securesoftware
from report_secureSoftware import craw_report_securesoftware
from report_edb import craw_title_edb
from report_edb import craw_report_edb
from report_securityFocus import craw_report_securityfocus_official
from report_securityTracker import craw_report_securitytracker
from report_sourceWare import craw_report_sourceware
from lxml import html
from getData import get_page
from getData import get_small_cve_ref
from getData import split_report_into_files
import requests
'''
程序入口
'''

BANNER = '''
      ┏┛ ┻━━━━━┛ ┻┓
      ┃　　　　　　 ┃
      ┃　　　━　　　┃
      ┃　┳┛　  ┗┳　┃
      ┃　　　　　　 ┃
      ┃　　　┻　　　┃
      ┃　　　　　　 ┃
      ┗━┓　　　┏━━━┛
        ┃　　　┃   神兽保佑
        ┃　　　┃   代码无BUG！
        ┃　　　┗━━━━━━━━━┓
        ┃　　　　　　　    ┣┓
        ┃　　　　         ┏┛
        ┗━┓ ┓ ┏━━━┳ ┓ ┏━┛
          ┃ ┫ ┫   ┃ ┫ ┫
          ┗━┻━┛   ┗━┻━┛
'''


if __name__ == "__main__":
    '''
    1.先在项目同级目录新建3个文件夹：cve_id、cve_ref和report，cve_id和cve_ref里的文件可以从我这里复制
    2.已经执行craw_reference()生成了cve_ref文件了，只需要在调试程序之后删除下面的调试程序而运行craw_report()即可。
    3.根据下面列出的用于测试的cve，进行调试即可。
    '''
    # craw_reference()
    # get_small_cve_ref()
    craw_report()
    # split_report_into_files()
    '''
    用于测试的cve（有的link暂时没找到对应的cve_id）：
    bugsGentoo:
        link = 'https://bugs.gentoo.org/74478'
    edb:
        cve_id = 'CVE-2007-5301'
        link = 'https://www.exploit-db.com/exploits/5424'
    marcInfo:
        cve_id = 'CVE-2011-5320'
        link = 'https://marc.info/?l=gimp-developer&m=129567990905823&w=2'
    nvd:
        cve_id = 'CVE-2006-4206'
        link = 'https://nvd.nist.gov/vuln/detail/CVE-2006-4206'
    seclist:
        cve_id = 'CVE-1999-0108'
        link = 'http://seclists.org/bugtraq/1997/May/191'
    securesoftware:
        link = 'http://securesoftware.list.cr.yp.to/archive/0/53'
    securityfocus_normal:
        cve_id:CVE-2001-0204
        link:http://www.securityfocus.com/archive/1/162965
    securityfocus_official:
        cve_id:CVE-1999-0003
        link: https://www.securityfocus.com/bid/122
    securitytracker:
        cve_id:CVE-1999-0377
        link: https://www.securitytracker.com/id/1033881
    sourceware:
        cve_id:CVE-2006-2362
        link: http://sourceware.org/bugzilla/show_bug.cgi?id=2584
    '''

'''
    cve_id = 'CVE-1999-0108'
    link = 'http://seclists.org/bugtraq/1997/May/191'
    dict_to_write = {}   # 用字典存储所有的报告信息
    dict_to_write[cve_id] = {'cve': {}, 'edb': {}, 'bugsGentoo': {}, 'marcInfo': {}, 'nvd': {}, 'seclists': {},
                             'secureSoftware': {}, 'securityFocus': {}, 'securityFocusOfficial': {},
                             'securityTracker': {},'sourceWare': {}}

    # 调试函数craw_report_xxx()
    dict_to_write = craw_report_seclists(cve_id, link, dict_to_write)
'''
