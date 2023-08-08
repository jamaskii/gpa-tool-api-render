from flask import Flask, render_template, send_file, request
import requests
import io
import base64
import json
import re
from urllib import parse


app = Flask(__name__)


@app.route('/')
def route_root():
    return render_template('index.html')

@app.route('/api/vcimg')
def route_api_vcimg():
    body = {
        'success': False,
        'msg': '',
        'data': {
            'image': '',
            'token': ''
        }
    }
    try:
        headers = { 'content-type': 'application/json' }
        resp = requests.get('http://jw.gxmu.edu.cn/jsxsd/verifycode.servlet')
        token = resp.cookies['JSESSIONID']
        body['success'] = True
        body['data']['image'] = base64.b64encode(resp.content).decode('utf-8')
        body['data']['token'] = token
    except Exception as e:
        body['msg'] = str(e)
    
    return json.dumps(body, ensure_ascii=False, indent=4), headers
        
@app.route('/vcimg')
def route_vcimg():
    try:
        resp = requests.get('http://jw.gxmu.edu.cn/jsxsd/verifycode.servlet')
        token = resp.cookies['JSESSIONID']
        cookie = 'JSESSIONID=%s;' %(token,)
        headers = {
            'content-type': 'image/jpeg',
            'set-cookie': cookie
        }
        body = send_file(
            io.BytesIO(resp.content),
            mimetype='image/jpeg'
        )
        return body, 200, headers
    except Exception as e:
        return render_template('error.html', title='内部错误', content=str(e)), 500

@app.route('/api/login')
def route_api_login():
    body = {
        'success': False,
        'msg': '',
        'data': {}
    }
    headers = { 'content-type': 'application/json' }
    username = request.args.get('username')
    password = request.args.get('password')
    vcode    = request.args.get('vcode')
    token    = request.args.get('token')
    cookie   = request.headers.get('cookie')

    if username == None or password == None or vcode == None:
        body['msg'] = '请提供完整参数'
        return json.dumps(body, ensure_ascii=False), 200, headers
    if token == None and cookie == None:
        body['msg'] = '请提供token或传递cookie'
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    if token == None:
        try:
            token = re.findall(r'JSESSIONID=(.{32})', cookie)[1]
        except:
            pass
    cookie = 'JSESSIONID=%s;' %(token,)
    
    data = {
        'encoded': base64.b64encode(username.encode('utf-8')).decode('utf-8') + '%%%' + base64.b64encode(password.encode('utf-8')).decode('utf-8'),
        'RANDOMCODE': vcode
    }
    data = parse.urlencode(data)
    
    resp = None
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
        body['msg'] = '发起登录请求出错'
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    found = re.findall(r'color="red">(.+?)</font>', resp.content.decode('gbk'))
    if found:
        body['msg'] = '教务系统：' + found[0]
        return json.dumps(body, ensure_ascii=False), 200, headers
    
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
        body['msg'] = '获取成绩数据出错'
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    try:
        subjects = []
        rows = re.findall(r'<tr>([\s\S]+?)</tr>',resp.text)
        for row in rows:
            cells = re.findall(r'<td[\s\S]*?>(.*?)</td>',row)
            subject = {}
            try:
                subject['semester'] = cells[1]
                subject['name']     = cells[3]
                subject['score']    = re.findall(r'>(.+?)</a>',cells[4])[0]
                subject['detail']   = 'http://jw.gxmu.edu.cn' + re.findall(r'openWindow\(([\s\S]+?),', cells[4])[0][1:-1]
                subject['credit']   = cells[5]
                subject['point']    = cells[7]
                subject['type']     = cells[9]
                subjects.append(subject)
            except:
                continue
        body['success'] = True
        body['data']['semesters'] = sort_subjects(subjects)
        return json.dumps(body, ensure_ascii=False), 200, headers
    except:
        body['msg'] = '解析成绩数据出错'
        return json.dumps(body, ensure_ascii=False), 200, headers


def sort_subjects(subjects):
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