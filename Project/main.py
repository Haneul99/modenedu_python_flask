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
import time
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, render_template, g, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

#데이터베이스 환경 설정
DATABASE = 'twit.db'
PER_PAGE = 10
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
    rv = g.db.execute(sql, [username]).fetchone()  #하나만 가져옴
    return rv[0] if rv else None


@app.before_request
def before_request():
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']],
                          one=True)


#request가 들어올 때 마다 이 함수가 실행됨.


def format_datetime(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')


# gravatar.com에서 제공하는 이미지 서비스를 받기 위한 함수
def gravatar_url(email, size=80):  #email에 대해 해싱
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d'  % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)# 앞은 %s, size는 %d로 값이 넘어감


@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):  #global 객체에 db가 있으면 db 접속 종료
        g.db.close()


#request hooking 처리


@app.route('/public')
def public_twit():
    sql = ''' SELECT message.*, user.* FROM message, user WHERE message.author_id = user.user_id 
            order by message.pub_date desc limit ?'''
    messages = query_db(sql, [PER_PAGE])
    return render_template('twit_list.html', messages=messages)


@app.route('/')
def twit_list():
    if not g.user:
        return redirect(url_for('public_twit'))
    sql = '''SELECT message.*, user.* FROM message, user WHERE message.author_id = user.user_id
            and (user.user_id = ? or user.user_id in (SELECT whom_id FROM follower WHERE who_id = ?))
            order by message.pub_date desc limit ?'''#내 트윗 or 내 팔로잉의 트윗
    messages = query_db(sql, [session['user_id'], session['user_id'], PER_PAGE])

    return render_template('twit_list.html', messages=messages)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('twit_list'))
    error = None
    if request.method == 'POST':
        ## 유효성 검사
        if not request.form['username']:
            error = "사용자 이름을 입력하세요"
        elif not request.form['email'] or '@' not in request.form['email']:
            error = " 잘못된 이메일 형식이거나 이메일을 입력하지 않으셨습니다"
        elif not request.form['password']:
            error = "비밀번호를 입력하세요"
        elif request.form['password'] != request.form['password2']:
            error = "비밀번호가 일치하지 않습니다"
        elif get_user_id(
                request.form['username']) is not None:  # 등록된 사용자가 아닌지 검사하는 코드
            error = "이미 등록된 사용자 입니다"
        else:
            #데이터베이스에 등록하기
            sql = "INSERT INTO user (username, email, pw_hash) VALUES( ?, ?, ? )"
            # 비밀번호를 DB에 저장할 때 평문이 아닌 암호문을  저장하기 위한 해시함수
            # 이때 해시 함수는 백자이그에서 제공하는 함수이다. --->generate_password_hash()
            g.db.execute(sql, [
                request.form['username'], request.form['email'],
                generate_password_hash(request.form['password'])
            ])
            g.db.commit()

            flash('사용자 등록이 완료 되었습니다. 로그인을 하실 수 있습니다.')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/<username>/follow')
def follow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    sql = 'INSERT INTO follower(who_id, whom_id) VALUES (?, ?)'
    g.db.execute(sql, [session['user_id'], whom_id])
    g.db.commit()
    flash('지금 "%s"를 팔로우 했습니다' % username)
    return redirect(url_for('user_twit', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    sql = 'DELETE FROM follower WHERE who_id = ? and whom_id = ?'
    g.db.execute(sql, [session['user_id'], whom_id])
    g.db.commit()
    flash('"%s"를 언팔로우 처리 했습니다' % username)
    return redirect(url_for('user_twit', username=username))


@app.route('/<username>')
def user_twit(username):
    sql = 'SELECT * FROM user WHERE username =?'
    profile_user = query_db(sql, [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    # 자신의 팔로워 인지 확인
    if g.user:
        sql = 'SELECT 1 FROM follower WHERE follower.who_id = ? and follower.whom_id = ?'  #Table의 개수만큼 1을 가져옴. 빠르게 수행하려고 할 때 사용
        followed = query_db(sql, [session['user_id'], profile_user['user_id']],
                            one=True) is not None
    #자신의 팔로워를 확인한 후 팔로워의 메시지를 조회한다.
    sql = '''SELECT message.*, user.* FROM message, user 
             WHERE message.author_id = user.user_id and user.user_id = ?
             order by message.pub_date desc limit ? '''
    messages = query_db(sql, [profile_user['user_id'], PER_PAGE])
    return render_template('twit_list.html',
                           messages=messages,
                           followed=followed,
                           profile_user=profile_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('twit_list'))
    error = None
    if request.method == 'POST':
        # 유효성 검사
        sql = "SELECT * FROM user WHERE username = ?"
        user = query_db(sql, [request.form['username']], one=True)
        print(request.form['username'])
        print(user)
        if user is None:
            error = "사용자 이름이 일치하지 않습니다. 다시 확인하세요"
        # check_password_hash() 함수는 해시화된 암호와 사용자가 입력한 평문 형태의 암호를 비교하는 함수
        # 두개의 값이 서로 일치하면 True, False
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = "비밀번호가 일치하지 않습니다. 다시 확인하세요"
        else:
            flash("로그인 성공")
            session['user_id'] = user['user_id']
            return redirect(url_for('twit_list'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    flash('로그아웃 되었습니다')  #session의 user_id 값을 pop해서 삭제
    session.pop('user_id', None)
    return redirect(url_for('twit_list'))


@app.route('/add_message', methods=['POST'])  #message는 내용이 길기 때문에 POST만 사용
def add_message():
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        sql = "INSERT INTO message(author_id, text, pub_date) VALUES (?, ?, ?)"
        g.db.execute(
            sql, (session['user_id'], request.form['text'], int(time.time())))
        g.db.commit()
        flash("메시지가 저장되었습니다.")
    return redirect(url_for('twit_list'))


# 진자 템플릿에 필터 설정
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == "__main__":
    init_db()
    app.run('0.0.0.0')
