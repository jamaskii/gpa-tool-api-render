from flask import Flask, render_template, send_file, request
import io
import json

import gpa


app = Flask(__name__)


@app.route('/')
def route_root():
    return render_template('index.html')
        

@app.route('/vcimg')
def route_vcimg():
    try:
        err, image, cookie = gpa.get_verifycode()
        if err != None:
            return render_template('error.html', title='内部错误', content=str(err)), 500
        
        body = send_file(
            io.BytesIO(image),
            mimetype='image/jpeg'
        )
        headers = {
            'content-type': 'image/jpeg',
            'set-cookie': cookie + 'Path=/;'
        }
        return body, 200, headers
    except Exception as e:
        return render_template('error.html', title='内部错误', content=str(e)), 500

@app.route('/api/login')
def route_api_login():
    body = {
        'success': False,
        'msg': ''
    }
    headers = { 'content-type': 'application/json' }
    username = request.args.get('username')
    password = request.args.get('password')
    vcode    = request.args.get('vcode')
    cookie   = request.headers.get('cookie')

    if username == None or password == None or vcode == None:
        body['msg'] = '请提供完整参数'
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    if cookie == None:
        body['msg'] = '未传递Cookie'
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    err = gpa.login(username, password, vcode, cookie)
    if err != None:
        body['msg'] = err
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    body['success'] = True
    return json.dumps(body, ensure_ascii=False), 200, headers


@app.route('/api/scores')
def route_api_scores():
    body = {
        'success': False,
        'msg': '',
        'data': {}
    }
    headers = { 'content-type': 'application/json' }
    cookie   = request.headers.get('cookie')

    if cookie == None:
        body['msg'] = '未传递Cookie'
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    err, semesters = gpa.get_semesters(cookie)
    if err != None:
        body['msg'] = err
        return json.dumps(body, ensure_ascii=False), 200, headers
    
    body['success'] = True
    body['data']['semesters'] = semesters
    return json.dumps(body, ensure_ascii=False), 200, headers