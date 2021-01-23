#트윗 어플리케이션
"""
    [ 구현 기능 ]
    1. 사용자 등록 기능
    2. 로그인 / 로그아웃
    3. 트윗 글 등록
    4. follow / unfollow
    5. 글목록(사용자, 공용)

    [ 기술 요소 ]
    -데이터베이스(Sqlite)이용
    -gravatar 이용
    -비밀번호 해싱
    -jinja2 템플릿 엔진

"""
from sqlite3 import dbapi2 as sqlite3
from contextlib import closing
from hashlib import md5
from flask import Flask, request, session, url_for, redirect, render_template, g, flash
from werkzeug.security import generate_password_hash, check_password_hash

#데이터베이스 환경 설정
DATABASE = 'twit.db'
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)  #sqlite3의 환경설정, config를 읽어오는 코드


def connect_db():
    return sqlite3.connect(app.config['DATABASE'])


#one = True이면 전체 레코드 중 첫번째 row만을 가져온다. False면 전체 레코드를 가져온다는 뜻
def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [
        dict((cur.description[idx][0], value) for idx, value in enumerate(row))
        for row in cur.fetchall()
    ]
    #cursor fetch 후 row에 하나씩 넣어줌. 그 row를 enumerate 돌려서 idx, value로 dict를 만듦
    return (rv[0] if rv else None) if one else rv


#database init
def init_db():
    with closing(connect_db(
    )) as db:  #with closing() 블럭이 끝나는 시점에 인자로 받은 객체(connect_db)를 닫거나 제거
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()  #commit 후 db가 생성되면 db가 닫히게 됨

def get_user_id(username):
  sql = "SELECT user_id FROM user WHERE username = ?"
  rv = g.db.execute(sql,[username]).fetchone()#하나만 가져옴
  return rv[0] if rv else None

@app.before_request
def before_request():
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db(
            'select * from user where user_id = ?', [session['user_id']],
            one=True)


@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):  #global 객체에 db가 있으면 db 접속 종료
        g.db.close()


#request hooking 처리


@app.route('/')
def twit_list():
    return render_template('twit_list.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    #유효성 검사
    if request.method == 'POST':
      if not request.form['username']:
        error = "사용자 이름을 입력하세요"
      elif not request.form['email'] or '@' not in request.form['email']:
        error = "잘못된 이메일 형식이거나 이메일을 입력하지 않았습니다"
      elif not request.form['password']:
        error = "비밀번호를 입력하세요"
      elif request.form['password'] != request.form['password2']:
        error = "비밀번호가 일치하지 않습니다"
      elif get_user_id(request.form['username']) is not None: #이미 등록된 사용자인지 검사
        error = "이미 등록된 사용자입니다"
      else:#데이터베이스에 등록하기
        sql = "INSERT INTO user (username, email, pw_hash) VALUES(?, ?, ?)"
        # 비밀번호를 DB에 저장할 때 평문이 아닌 암호문을 저장하기 위한 해시 함수
        # 이때 해시 함수는 백자이그에서 제공하는 함수 -> generate_password_hash()
        g.db.execute(sql, [request.form['username'], request.form['email'], generate_password_hash(request.form['password'])])
        g.db.commit()

        flash("사용자 등록이 완료 되었습니다. 로그인을 하실 수 있습니다")
        return redirect(url_for('login'))#jinja2에서는 url_for 뒤에 함수가 옴.
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    #유효성 검사
    if request.method == 'POST':
      sql = "SELECT * FROM user WHERE username = ?"
      user = query_db(sql, [request.form['username']], one=True)
      if user is None:
        error = "사용자 이름이 일치하지 않습니다. 다시 확인하세요"
      # check_password_hash() 함수는 해시화된 암호와 사용자가 입력한 평문 형태의 암호를 비교하는 함수
      # 두 값이 같으면 True, 아니면 False return
      elif not check_password_hash(user['pw_hash'], request.form['password']):
        error = "비밀번호가 일치하지 않습니다. 다시 확인하세요"
      else:
        flash("로그인 성공")
        session['user_id'] = user['user_id']
        return redirect(url_for('twit_list'))
    return render_template('login.html', error=error)


if __name__ == "__main__":
    init_db()
    app.run('0.0.0.0')
