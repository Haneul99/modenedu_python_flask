#메시지 플래싱(Message Flashing) - 플라스크에서 제공하는 플래싱 시스템
#요청의 끝에 메시지를 기록하고 그 다음 요청에서만 그 메시지를 접근할 수 있도록 하는 기능

from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)

app.secret_key = 'some_secret'

@app.route('/')
def index():
    return "hello World"
    #return render_template('index.html')

@app.route('/flash_login', methods=['GET', 'POST'])
def flash_login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'secret':
            error = 'login error'
        else:
            flash('로그인 성공')
            return redirect(url_for('index'))
    return render_template('flash_login.html', error = error)

if __name__ =="__main__":
     app.run('0.0.0.0')
