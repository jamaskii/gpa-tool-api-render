import requests
import base64
import re
from urllib import parse


def get_verifycode():
    try:
        resp = requests.get('http://jw.gxmu.edu.cn/jsxsd/verifycode.servlet')
        token = resp.cookies['JSESSIONID']
        cookie = 'JSESSIONID=%s;' %(token,)
        return None, resp.content, cookie
    except Exception as e:
        return e, None, None
    

def login(username:str, password:str, verifycode:str, cookie:str):
    data = {
        'encoded': base64.b64encode(username.encode('utf-8')).decode('utf-8') + '%%%' + base64.b64encode(password.encode('utf-8')).decode('utf-8'),
        'RANDOMCODE': verifycode
    }
    data = parse.urlencode(data)
    try:
        resp = requests.post(
            'http://jw.gxmu.edu.cn/jsxsd/xk/LoginToXk',
            headers={
                'Accept':           'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding':  'gzip,deflate',
                'Accept-Language':  'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Connection':       'keep-alive',
                'Content-Type':     'application/x-www-form-urlencoded',
                'Cookie':           cookie,
                'Host':             'jw.gxmu.edu.cn',
                'Origin':           'http://jw.gxmu.edu.cn',
                'Referer':          'http://jw.gxmu.edu.cn/jsxsd/',
                'Upgrade-Insecure-Requests':'1',
                'User-Agent':       'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:77.0)Gecko/20100101Firefox/77.0'
            },
            data=data)
    except:
        return '发起登录请求出错'
    
    found = re.findall(r'color="red">(.+?)</font>', resp.content.decode('gbk'))
    if found:
        return '教务系统：' + found[0]
    else:
        return None
    

def get_subjects(cookie:str, sort:bool=False):
    try:
        resp = requests.post(
            'http://jw.gxmu.edu.cn/jsxsd/kscj/cjcx_list',
            headers={
                'Accept':           'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding':  'gzip,deflate',
                'Accept-Language':  'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Connection':       'keep-alive',
                'Content-Type':     'application/x-www-form-urlencoded',
                'Cookie':cookie,
                'Host':             'jw.gxmu.edu.cn',
                'Origin':           'http://jw.gxmu.edu.cn',
                'Referer':          'http://jw.gxmu.edu.cn/jsxsd/',
                'Upgrade-Insecure-Requests':'1',
                'User-Agent':       'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:77.0)Gecko/20100101Firefox/77.0'
                },
            data='kksj=&kcxz=&kcmc=&xsfs=all')
    except:
        return '获取成绩数据出错：', None
    
    try:
        subjects = []
        rows = re.findall(r'<tr>([\s\S]+?)</tr>',resp.text)
        for row in rows:
            cells = re.findall(r'<td[\s\S]*?>(.*?)</td>',row)
            subject = {}
            try:
                subject['semester'] = cells[1]
                subject['name']     = cells[3]
                subject['score']    = float(re.findall(r'>(.+?)</a>',cells[4])[0])
                subject['detail']   = 'http://jw.gxmu.edu.cn' + re.findall(r'openWindow\(([\s\S]+?),', cells[4])[0][1:-1]
                subject['credit']   = float(cells[5])
                subject['point']    = float(cells[7])
                subject['type']     = cells[9]
                subjects.append(subject)
            except:
                continue
        return None, __sort_subjects(subjects) if sort else subject
    except:
        return '解析成绩数据出错', None
    

def get_semesters(cookie:str):
    return get_subjects(cookie, True)


def __sort_subjects(subjects):
    semesters = []
    for subject in subjects:
        semester = None
        for one in semesters:
            if one['name'] == subject['semester']:
                semester = one
                break
        if semester == None:
            semester = {
                'name': subject['semester'],
                'subjects': [subject]
            }
            semesters.append(semester)
        else:
            semester['subjects'].append(subject)
    return semesters