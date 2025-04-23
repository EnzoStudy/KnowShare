from flask import Flask, render_template, request, redirect, url_for, make_response, abort, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
import os
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///qna.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS 환경에서만
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 2 * 1024 * 1024))

UPLOAD_EXTENSIONS = os.getenv('UPLOAD_EXTENSIONS', '.jpg,.png,.gif,.pdf').split(',')
UPLOAD_PATH = os.getenv('UPLOAD_PATH', 'uploads')

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# 업로드 경로 생성
if not os.path.exists(UPLOAD_PATH):
    os.makedirs(UPLOAD_PATH)

# OAuth 설정
oauth = OAuth(app)
ms = oauth.register(
    name='microsoft',
    client_id=os.getenv('MS_CLIENT_ID'),
    client_secret=os.getenv('MS_CLIENT_SECRET'),
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    access_token_params=None,
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    authorize_params=None,
    api_base_url='https://graph.microsoft.com/v1.0/',
    userinfo_endpoint='https://graph.microsoft.com/oidc/userinfo',
    client_kwargs={'scope': 'openid profile email'},
)

# 데이터베이스 모델 정의
CATEGORY_LIST = [
    '자유', 'IT', '생활', '교육', '건강', '취미', '여행', '경제', '기타'
]

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    answer_count = db.Column(db.Integer, default=0)
    delete_token = db.Column(db.String(64), nullable=False)
    nickname = db.Column(db.String(32), nullable=True)  # 작성자 닉네임
    category = db.Column(db.String(32), nullable=False, default='자유')

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    delete_token = db.Column(db.String(64), nullable=False)
    nickname = db.Column(db.String(32), nullable=True)  # 작성자 닉네임
    is_selected = db.Column(db.Boolean, default=False)  # 채택 여부

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(10), nullable=False)  # 'question' or 'answer'
    target_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 닉네임 쿠키
NICKNAME_COOKIE = 'qna_nickname'
def get_or_set_nickname(resp=None):
    # MS 로그인 세션 우선
    if 'ms_name' in session:
        return session['ms_name']
    nickname = request.cookies.get(NICKNAME_COOKIE)
    if not nickname:
        nickname = '익명'
        if resp:
            resp.set_cookie(NICKNAME_COOKIE, nickname, max_age=60*60*24*30)
    return nickname

# 익명 인증용 토큰 발급
TOKEN_COOKIE = 'qna_token'
def get_or_set_token(resp=None):
    token = request.cookies.get(TOKEN_COOKIE)
    if not token:
        token = secrets.token_hex(16)
        if resp:
            resp.set_cookie(TOKEN_COOKIE, token, max_age=60*60*24*30)  # 30일
    return token

# 질문 목록
@app.route('/')
def index():
    sort = request.args.get('sort', 'latest')
    search = request.args.get('search', '').strip()
    search_type = request.args.get('search_type', 'title')
    category = request.args.get('category', '')
    nickname_filter = request.args.get('nickname', '').strip()
    date_filter = request.args.get('date', '').strip()
    solved = request.args.get('solved')
    query = Question.query
    if category:
        query = query.filter(Question.category == category)
    if solved == '0':
        # 미해결: 채택된 답변이 하나도 없는 질문만
        from sqlalchemy import func
        subq = db.session.query(Answer.question_id).filter(Answer.is_selected == True).subquery()
        query = query.filter(~Question.id.in_(subq))
    if search:
        if search_type == 'title':
            query = query.filter(Question.title.contains(search))
        elif search_type == 'nickname':
            query = query.filter(Question.nickname.contains(search))
        elif search_type == 'date':
            # YYYY-MM-DD로 시작하는 질문만
            try:
                from datetime import datetime, timedelta
                day = datetime.strptime(search, '%Y-%m-%d')
                next_day = day + timedelta(days=1)
                query = query.filter(Question.created_at >= day, Question.created_at < next_day)
            except Exception:
                pass
        else:
            query = query.filter((Question.title.contains(search)) | (Question.content.contains(search)))
    if nickname_filter:
        query = query.filter(Question.nickname == nickname_filter)
    if date_filter:
        try:
            from datetime import datetime, timedelta
            day = datetime.strptime(date_filter, '%Y-%m-%d')
            next_day = day + timedelta(days=1)
            query = query.filter(Question.created_at >= day, Question.created_at < next_day)
        except Exception:
            pass
    if sort == 'views':
        questions = query.order_by(Question.views.desc()).all()
    elif sort == 'answers':
        questions = query.order_by(Question.answer_count.desc()).all()
    else:
        questions = query.order_by(Question.created_at.desc()).all()
    # 각 질문별 답변 목록 추가(채택여부 체크용)
    for q in questions:
        q.answers = Answer.query.filter_by(question_id=q.id).all()
    nickname = get_or_set_nickname()
    # 작성자 목록(중복 제거)
    nickname_list = [n[0] for n in db.session.query(Question.nickname).distinct().all() if n[0]]
    return render_template('index.html', questions=questions, sort=sort, nickname=nickname, search=search, search_type=search_type, category=category, category_list=CATEGORY_LIST, nickname_list=nickname_list, nickname_filter=nickname_filter, date_filter=date_filter)

# 질문 작성
@app.route('/ask', methods=['GET', 'POST'])
def ask():
    nickname = get_or_set_nickname()
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash('제목과 내용을 입력해주세요.')
            return redirect(url_for('ask'))
        if len(title) > 200 or len(content) > 2000:
            flash('입력 길이가 너무 깁니다.')
            return redirect(url_for('ask'))
        category = request.form.get('category', '자유')
        token = get_or_set_token()
        q = Question(title=title, content=content, delete_token=token, nickname=nickname, category=category)
        db.session.add(q)
        db.session.commit()
        resp = make_response(redirect(url_for('index')))
        get_or_set_token(resp)
        get_or_set_nickname(resp)
        return resp
    from flask_wtf.csrf import generate_csrf
    resp = make_response(render_template('ask.html', nickname=nickname, category_list=CATEGORY_LIST, csrf_token=generate_csrf()))
    get_or_set_token(resp)
    get_or_set_nickname(resp)
    return resp

# 질문 삭제
@app.route('/question/<int:qid>/delete', methods=['POST'])
def delete_question(qid):
    from flask_wtf.csrf import validate_csrf
    token = request.cookies.get('qna_token')
    q = Question.query.get_or_404(qid)
    try:
        validate_csrf(request.form.get('csrf_token'))
    except Exception:
        abort(400, 'CSRF token error')
    if q.delete_token != token:
        abort(403)
    # 답변도 같이 삭제
    Answer.query.filter_by(question_id=qid).delete()
    db.session.delete(q)
    db.session.commit()
    flash('질문이 삭제되었습니다.')
    return redirect(url_for('index'))

# 답변 삭제
@app.route('/answer/<int:aid>/delete', methods=['POST'])
def delete_answer(aid):
    from flask_wtf.csrf import validate_csrf
    token = request.cookies.get('qna_token')
    a = Answer.query.get_or_404(aid)
    try:
        validate_csrf(request.form.get('csrf_token'))
    except Exception:
        abort(400, 'CSRF token error')
    if a.delete_token != token:
        abort(403)
    db.session.delete(a)
    db.session.commit()
    flash('답변이 삭제되었습니다.')
    return redirect(request.referrer or url_for('index'))

# 질문 상세/답변 작성
@app.route('/question/<int:qid>', methods=['GET', 'POST'])
def question_detail(qid):
    q = Question.query.get_or_404(qid)
    nickname = get_or_set_nickname()
    if request.method == 'POST':
        content = request.form['content'].strip()
        if not content or len(content) > 2000:
            flash('답변 내용을 올바르게 입력해주세요.')
            return redirect(url_for('question_detail', qid=qid))
        token = get_or_set_token()
        a = Answer(question_id=qid, content=content, delete_token=token, nickname=nickname)
        db.session.add(a)
        q.answer_count += 1
        db.session.commit()
        resp = make_response(redirect(url_for('question_detail', qid=qid)))
        get_or_set_token(resp)
        get_or_set_nickname(resp)
        return resp
    q.views += 1
    db.session.commit()
    answers = Answer.query.filter_by(question_id=qid).order_by(Answer.created_at.asc()).all()
    selected_answer = next((a for a in answers if a.is_selected), None)
    from flask_wtf.csrf import generate_csrf
    resp = make_response(render_template('question.html', question=q, answers=answers, nickname=nickname, csrf_token=generate_csrf(), selected_answer=selected_answer))
    get_or_set_token(resp)
    get_or_set_nickname(resp)
    return resp

# 답변 채택
# 답변 채택 라우트는 CSRF 보호가 자동 적용됨 (POST)
@app.route('/select_answer/<int:aid>', methods=['POST'])
def select_answer(aid):
    answer = Answer.query.get_or_404(aid)
    question = Question.query.get(answer.question_id)
    # 질문 작성자만 채택 가능
    user_nickname = get_or_set_nickname()
    if question.nickname != user_nickname:
        abort(403)
    # 기존 채택 해제
    Answer.query.filter_by(question_id=question.id, is_selected=True).update({'is_selected': False})
    answer.is_selected = True
    db.session.commit()
    flash('답변이 채택되었습니다!')
    return redirect(url_for('question_detail', qid=question.id))

# 질문/답변 삭제
@app.route('/delete/<type>/<int:tid>', methods=['POST'])
@csrf.exempt  # CSRF 적용이 어려운 API라면 예외 처리, 아니면 제거
def delete_item(type, tid):
    token = get_or_set_token()
    if type == 'question':
        item = Question.query.get_or_404(tid)
    elif type == 'answer':
        item = Answer.query.get_or_404(tid)
    else:
        abort(400)
    if item.delete_token != token:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('index'))

# 신고 기능
@app.route('/report/<type>/<int:tid>', methods=['POST'])
def report_item(type, tid):
    reason = request.form.get('reason', '').strip()
    if not reason or len(reason) > 200:
        abort(400)
    r = Report(target_type=type, target_id=tid, reason=reason)
    db.session.add(r)
    db.session.commit()
    return '신고가 접수되었습니다.'

# MS 로그인
@app.route('/login/ms')
def login_ms():
    redirect_uri = os.getenv('MS_REDIRECT_URI')
    return ms.authorize_redirect(redirect_uri)

@app.route('/login/ms/callback')
def login_ms_callback():
    token = ms.authorize_access_token()
    userinfo = ms.get('https://graph.microsoft.com/v1.0/me').json()
    ms_name = userinfo.get('displayName') or userinfo.get('userPrincipalName')
    if ms_name:
        session['ms_name'] = ms_name
        flash(f"{ms_name}님, MS 계정으로 로그인되었습니다.")
    else:
        flash("MS 로그인에 실패했습니다.")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('ms_name', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 닉네임 설정
@app.route('/nickname', methods=['GET', 'POST'])
def set_nickname():
    if request.method == 'POST':
        nickname = request.form['nickname'].strip() or '익명'
        if len(nickname) > 32:
            flash('닉네임은 32자 이내로 입력해주세요.')
            return redirect(url_for('set_nickname'))
        resp = make_response(redirect(url_for('index')))
        resp.set_cookie(NICKNAME_COOKIE, nickname, max_age=60*60*24*30, httponly=True, secure=True)
        return resp
    nickname = get_or_set_nickname()
    from flask_wtf.csrf import generate_csrf
    resp = make_response(render_template('set_nickname.html', nickname=nickname, csrf_token=generate_csrf()))
    resp.set_cookie(NICKNAME_COOKIE, nickname, max_age=60*60*24*30, httponly=True, secure=True)
    return resp

# 관리자 카테고리 관리
@app.route('/admin/categories', methods=['GET', 'POST'])
def admin_categories():
    global CATEGORY_LIST
    from flask_wtf.csrf import generate_csrf
    if request.method == 'POST':
        cats = request.form.get('category_list', '')
        CATEGORY_LIST = [c.strip() for c in cats.split(',') if c.strip()]
        flash('카테고리 목록이 저장되었습니다.')
        return redirect(url_for('admin_categories'))
    resp = make_response(render_template('admin_categories.html', category_list=CATEGORY_LIST, csrf_token=generate_csrf()))
    return resp

# 관리자 답변자별 답변수 통계
@app.route('/admin/answer_stats')
def admin_answer_stats():
    stats = db.session.query(Answer.nickname, db.func.count(Answer.id)).group_by(Answer.nickname).order_by(db.func.count(Answer.id).desc()).all()
    return render_template('admin_answer_stats.html', stats=stats)

# 관리자 신고 내역
@app.route('/admin/reports')
def admin_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin_reports.html', reports=reports)

# ⚠️ DB 스키마가 변경되었으므로 기존 qna.db 파일을 삭제 후 재생성하거나, 마이그레이션을 해주세요.
if __name__ == '__main__':
    if not os.path.exists('qna.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
