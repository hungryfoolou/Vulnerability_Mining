#!/usr/bin/env python3
#coding: utf-8
import requests

s = requests.session()
url = "https://mail.163.com/"
url = 'http://www.baidu.com'
s.keep_alive = False
s.proxies = {"https": "183.195.145.174:5328", "http": "49.51.195.24:1080", }
s.headers = {'User-Agent': "Magic Browser"}
r = s.get(url, verify=False)
print(r.status_code)  # 如果代理可用则正常访问，不可用报以上错误