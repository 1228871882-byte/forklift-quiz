#!/usr/bin/env python3
"""企业培训考试系统 — Flask 单文件全功能版"""
import json, os, time, hashlib, hmac, base64, random, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, g

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data_v2')
os.makedirs(DATA_DIR, exist_ok=True)

# ===== 简单的 JWT（不需要额外库）=====
def create_token(user_id, role):
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "uid": user_id, "role": role, "iat": int(time.time()),
        "exp": int(time.time()) + 86400 * 7
    }).encode()).decode().rstrip('=')
    sig = hmac.new(app.secret_key.encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{header}.{payload}.{sig}"

def verify_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        header, payload, sig = parts
        expected = hmac.new(app.secret_key.encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()[:32]
        if sig != expected: return None
        data = json.loads(base64.urlsafe_b64decode(payload + '=='))
        if data.get('exp', 0) < time.time(): return None
        return data
    except: return None

# ===== JSON 数据库 =====
def db(name):
    p = os.path.join(DATA_DIR, f'{name}.json')
    if not os.path.exists(p): save_json(p, [] if name != 'settings' else {})
    with open(p, 'r') as f: return json.load(f)

def save_json(p, d):
    with open(p, 'w') as f: json.dump(d, f, ensure_ascii=False, indent=2)

def db_save(name, data):
    save_json(os.path.join(DATA_DIR, f'{name}.json'), data)

# ===== 认证 =====
def auth_required(f):
    @wraps(f)
    def decorator(*a, **kw):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token: token = request.cookies.get('token', '')
        user_data = verify_token(token) if token else None
        if not user_data:
            if request.path.startswith('/api/'): return jsonify({"code":401,"message":"请登录"}), 401
            return redirect(url_for('login_page'))
        g.user_id = user_data['uid']
        g.role = user_data['role']
        g.user = next((u for u in db('users') if u['id'] == g.user_id), None)
        return f(*a, **kw)
    return decorator

# ===== 页面路由 =====
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login_v2.html')

@app.route('/app')
@auth_required
def app_page():
    return render_template('app_v3.html')

# ===== API 路由 =====
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    users = db('users')
    user = next((u for u in users if u['username'] == username), None)
    if not user: return jsonify({"code":500,"message":"用户不存在"}), 200
    if user['password'] != password: return jsonify({"code":500,"message":"密码错误"}), 200
    token = create_token(user['id'], user['role'])
    resp = jsonify({"code":200,"message":"success","data":{
        "realName": user['name'], "departmentId": user.get('deptId',1),
        "userId": user['id'], "token": token, "username": user['username'],
        "role": user['role'], "department": user['department']
    }})
    resp.set_cookie('token', token, max_age=86400*7, httponly=True)
    return resp

@app.route('/api/user/info')
@auth_required
def api_user_info():
    u = g.user
    return jsonify({"code":200,"data":{
        "realName": u['name'], "department": u['department'],
        "role": u['role'], "userId": u['id'], "username": u['username']
    }})

@app.route('/api/question/list')
@auth_required
def api_question_list():
    cat = request.args.get('categoryId', '')
    qs = db('questions')
    if cat: qs = [q for q in qs if str(q.get('categoryId','')) == cat]
    return jsonify({"code":200,"data":qs})

@app.route('/api/question/categories')
@auth_required
def api_categories():
    cats = db('categories')
    return jsonify({"code":200,"data":cats})

@app.route('/api/question/random')
@auth_required
def api_random_questions():
    cat = request.args.get('categoryId', '')
    count = int(request.args.get('count', 20))
    qs = db('questions')
    if cat: qs = [q for q in qs if str(q.get('categoryId','')) == cat]
    if len(qs) > count:
        qs = random.sample(qs, count)
    return jsonify({"code":200,"data":qs})

@app.route('/api/exam/submit', methods=['POST'])
@auth_required
def api_submit_exam():
    data = request.get_json() or {}
    answers = data.get('answers', {})  # {qid: answer_string}
    qs = db('questions')
    
    correct = 0; total_score = 0; max_score = 0
    details = []
    for q in qs:
        if str(q['id']) not in answers: continue
        user_ans = answers[str(q['id'])].upper()
        correct_ans = q['answer'].upper()
        is_correct = (user_ans == correct_ans)
        if is_correct: correct += 1
        
        q_score = q.get('score', 5)
        max_score += q_score
        gained = q_score if is_correct else 0
        
        # Multi-choice partial credit
        if q['type'] == 'multi' and not is_correct and user_ans:
            c_set = set(correct_ans.replace(',','').replace(' ',''))
            u_set = set(user_ans.replace(',','').replace(' ',''))
            if u_set.issubset(c_set) and len(u_set) < len(c_set):
                gained = max(1, q_score // 2)
        
        total_score += gained
        details.append({
            "questionId": q['id'], "type": q['type'], "content": q['content'],
            "userAnswer": user_ans, "correctAnswer": correct_ans,
            "isCorrect": is_correct, "score": gained, "maxScore": q_score,
            "analysis": q.get('analysis',''), "options": q.get('options','{}')
        })
    
    # Save
    recs = db('records')
    record = {
        "id": len(recs) + 1, "userId": g.user_id, "userName": g.user['name'],
        "department": g.user['department'], "score": total_score, "maxScore": max_score,
        "correct": correct, "total": len(details),
        "time": datetime.now().strftime('%Y-%m-%d %H:%M'), "details": details
    }
    recs.append(record)
    db_save('records', recs)
    
    return jsonify({"code":200,"data":{
        "recordId": record['id'], "score": total_score, "maxScore": max_score,
        "correct": correct, "total": len(details), "details": details
    }})

@app.route('/api/score/my')
@auth_required
def api_my_scores():
    recs = [r for r in db('records') if r['userId'] == g.user_id]
    recs.sort(key=lambda x: x['time'], reverse=True)
    return jsonify({"code":200,"data":[
        {"id":r['id'],"score":r['score'],"maxScore":r['maxScore'],
         "correct":r['correct'],"total":r['total'],"time":r['time']} for r in recs
    ]})

@app.route('/api/score/detail/<int:rid>')
@auth_required
def api_score_detail(rid):
    r = next((x for x in db('records') if x['id'] == rid), None)
    if not r: return jsonify({"code":500,"message":"不存在"})
    if g.role == 'employee' and r['userId'] != g.user_id: return jsonify({"code":403})
    return jsonify({"code":200,"data":r})

@app.route('/api/score/all')
@auth_required
def api_all_scores():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    dept = request.args.get('department','')
    recs = db('records')
    if dept: recs = [r for r in recs if r.get('department','') == dept]
    if g.role == 'manager':
        recs = [r for r in recs if r.get('department','') == g.user.get('department','')]
    recs.sort(key=lambda x: x['time'], reverse=True)
    return jsonify({"code":200,"data":recs[:100]})

@app.route('/api/statistics/overview')
@auth_required
def api_overview():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    recs = db('records')
    users = db('users')
    qs = db('questions')
    
    if g.role == 'manager':
        dept = g.user.get('department','')
        recs = [r for r in recs if r.get('department','') == dept]
    
    emp_users = [u for u in users if u['role'] == 'employee']
    total_exams = len(recs)
    avg_score = round(sum(r['score'] for r in recs)/len(recs), 1) if recs else 0
    pass_count = sum(1 for r in recs if r['score'] >= 80)
    pass_rate = round(pass_count/total_exams*100, 1) if total_exams else 0
    
    # Per department stats
    depts = {}
    for r in recs:
        d = r.get('department','未知')
        if d not in depts: depts[d] = {'total':0,'scores':[],'pass':0}
        depts[d]['total'] += 1
        depts[d]['scores'].append(r['score'])
        if r['score'] >= 80: depts[d]['pass'] += 1
    
    dept_list = []
    for d, s in depts.items():
        dept_list.append({
            "department": d, "total": s['total'],
            "avgScore": round(sum(s['scores'])/len(s['scores']),1),
            "passRate": round(s['pass']/s['total']*100,1)
        })
    
    return jsonify({"code":200,"data":{
        "totalExams": total_exams, "totalUsers": len(emp_users),
        "avgScore": avg_score, "passRate": pass_rate,
        "totalQuestions": len(qs), "departmentStats": dept_list
    }})

@app.route('/api/statistics/trend')
@auth_required
def api_trend():
    uid = request.args.get('userId', '')
    recs = db('records')
    if uid:
        recs = [r for r in recs if str(r['userId']) == uid]
    elif g.role == 'employee':
        recs = [r for r in recs if r['userId'] == g.user_id]
    recs.sort(key=lambda x: x['time'])
    return jsonify({"code":200,"data":[
        {"time":r['time'],"score":r['score'],"maxScore":r['maxScore']} for r in recs
    ]})

@app.route('/api/department/list')
@auth_required
def api_depts():
    depts = list(set(u['department'] for u in db('users')))
    return jsonify({"code":200,"data":[{"id":i+1,"name":d} for i,d in enumerate(depts)]})

@app.route('/api/user/list')
@auth_required
def api_user_list():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    users = db('users')
    if g.role == 'manager':
        dept = g.user.get('department','')
        users = [u for u in users if u['department'] == dept]
    return jsonify({"code":200,"data":[{
        "id":u['id'],"username":u['username'],"name":u['name'],
        "department":u['department'],"role":u['role']
    } for u in users]})

@app.route('/api/user/add', methods=['POST'])
@auth_required
def api_add_user():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    data = request.get_json() or {}
    users = db('users')
    new_u = {
        "id": max([u['id'] for u in users], default=0) + 1,
        "username": data.get('username',''),
        "password": data.get('password','123456'),
        "name": data.get('name',''),
        "department": data.get('department','通用'),
        "role": data.get('role','employee')
    }
    users.append(new_u)
    db_save('users', users)
    return jsonify({"code":200,"message":"添加成功"})

@app.route('/api/user/reset-password', methods=['POST'])
@auth_required
def api_reset_pwd():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    data = request.get_json() or {}
    uid = data.get('userId')
    users = db('users')
    for u in users:
        if u['id'] == uid:
            u['password'] = '123456'
            break
    db_save('users', users)
    return jsonify({"code":200,"message":"已重置为123456"})

@app.route('/api/question/add', methods=['POST'])
@auth_required
def api_add_question():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    data = request.get_json() or {}
    qs = db('questions')
    new_q = {
        "id": max([q['id'] for q in qs], default=0) + 1,
        "categoryId": data.get('categoryId', 1),
        "type": data.get('type', 'single'),
        "content": data.get('content', ''),
        "options": data.get('options', '{}'),
        "answer": data.get('answer', ''),
        "analysis": data.get('analysis', ''),
        "difficulty": data.get('difficulty', 1),
        "score": data.get('score', 5)
    }
    qs.append(new_q)
    db_save('questions', qs)
    return jsonify({"code":200,"message":"添加成功"})

@app.route('/api/question/delete', methods=['POST'])
@auth_required
def api_delete_question():
    if g.role not in ('admin','manager'): return jsonify({"code":403})
    data = request.get_json() or {}
    qid = data.get('id')
    qs = [q for q in db('questions') if q['id'] != qid]
    db_save('questions', qs)
    return jsonify({"code":200,"message":"删除成功"})

@app.route('/api/category/add', methods=['POST'])
@auth_required
def api_add_category():
    if g.role != 'admin': return jsonify({"code":403})
    data = request.get_json() or {}
    cats = db('categories')
    new_c = {"id": max([c['id'] for c in cats], default=0)+1, "name": data.get('name',''), "sortOrder": len(cats)}
    cats.append(new_c)
    db_save('categories', cats)
    return jsonify({"code":200,"message":"添加成功"})

@app.route('/api/change-password', methods=['POST'])
@auth_required
def api_change_pwd():
    data = request.get_json() or {}
    old = data.get('oldPassword','')
    new = data.get('newPassword','')
    users = db('users')
    for u in users:
        if u['id'] == g.user_id:
            if u['password'] != old: return jsonify({"code":500,"message":"旧密码错误"})
            u['password'] = new
            break
    db_save('users', users)
    return jsonify({"code":200,"message":"修改成功"})

# ===== 初始化数据 =====
def init():
    if not os.path.exists(os.path.join(DATA_DIR, 'users.json')):
        db_save('users', [
            {"id":1,"username":"admin","password":"admin123","name":"总管理员","department":"总部","role":"admin","deptId":0},
            {"id":2,"username":"leader","password":"123456","name":"仓库主管王","department":"仓库一部","role":"manager","deptId":1},
            {"id":3,"username":"wl","password":"123456","name":"物流主管李","department":"物流部","role":"manager","deptId":2},
            {"id":4,"username":"zhuy","password":"123456","name":"朱媛","department":"仓库一部","role":"employee","deptId":1},
            {"id":5,"username":"emp2","password":"123456","name":"李四","department":"仓库一部","role":"employee","deptId":1},
            {"id":6,"username":"emp3","password":"123456","name":"王五","department":"物流部","role":"employee","deptId":2},
        ])
    if not os.path.exists(os.path.join(DATA_DIR, 'categories.json')):
        db_save('categories', [
            {"id":1,"name":"仓库管理","sortOrder":0},
            {"id":2,"name":"数据组","sortOrder":1},
            {"id":3,"name":"物流部","sortOrder":2},
            {"id":4,"name":"通用规范","sortOrder":3},
        ])
    if not os.path.exists(os.path.join(DATA_DIR, 'questions.json')):
        db_save('questions', load_questions())
    if not os.path.exists(os.path.join(DATA_DIR, 'records.json')):
        db_save('records', [])

def load_questions():
    qs = []
    data = [
        (1,"single","叉车司机上岗必须满足的着装要求是？",'{"A":"驾驶证、穿工作服、戴手套","B":"持证上岗、穿反光背心、戴安全帽","C":"持证上岗、可穿短裤、戴安全帽","D":"只需穿工作服即可，无需持证"}',"B","需持证上岗，穿反光背心、戴安全帽，严禁穿短裤/赤膊上岗。"),
        (1,"single","每日上班前，叉车司机的正确做法是？",'{"A":"点检叉车、确认性能完好、登记维保检查表后方可作业","B":"直接启动叉车开始作业","C":"只需检查油量即可","D":"每周点检一次即可"}',"A","每日上班前必须点检叉车，做好日常维保检查、确认性能完好、登记维保检查表后方可作业。"),
        (1,"single","下班后，电动叉车电量低于多少时需在指定区域充电？",'{"A":"≤30%","B":"≤40%","C":"≤50%","D":"≤20%"}',"B","规范明确：电叉≤40%电量时须在指定区域充电。"),
        (1,"single","17.5米货车应使用几叉进行叉运作业？",'{"A":"二叉","B":"二叉半","C":"三叉","D":"四叉"}',"D","按标准执行：9.6米双叉、13.75米三叉、17.5米四叉。"),
        (1,"single","仓库内吸烟或酒后驾驶叉车，扣绩效多少元/次？",'{"A":"200元","B":"500元","C":"1000元","D":"2000元"}',"C","仓库内吸烟、酒后驾驶属于严重违规，扣绩效1000元/次。"),
        (1,"single","叉车行驶速度限制为？",'{"A":"超10KM/H（弯道超5KM/H）","B":"超8KM/H（弯道超3KM/H）","C":"超15KM/H（弯道超8KM/H）","D":"超5KM/H（弯道超2KM/H）"}',"B","车速超8KM/H（弯道超3KM/H）即属违规。"),
        (1,"single","托盘离地超过多少厘米属于违规操作？",'{"A":"20CM","B":"50CM","C":"30CM","D":"40CM"}',"C","托盘离地超30CM属于违规，扣绩效100元/次。"),
        (1,"single","货物上架摆放规范中，托盘应放在货架什么位置？",'{"A":"靠左放置","B":"靠右放置","C":"正中位置（前后各10cm）","D":"任意位置均可"}',"C","货物上架需规范：托盘放货架正中，前后各10cm。"),
        (1,"single","装车完成后，出库单应如何处理？",'{"A":"叉车司机自行保管","B":"一车一单交予制单员","C":"放在货物上随车带走","D":"直接丢弃"}',"B","装车完成后，出库单需一车一单交予制单员。"),
        (1,"single","1000元考核内处罚，月累计几次会被劝退？",'{"A":"2次","B":"1次","C":"3次","D":"4次"}',"A","1000元考核内处罚，月累计≥2次将被劝退。"),
        (4,"multi","以下哪些属于叉车司机必须遵守的基础作业规范？（多选）",'{"A":"持证上岗，穿反光背心、戴安全帽","B":"每日上班前点检叉车并登记维保检查表","C":"下班后叉车可任意停放","D":"当日工作当日毕","E":"下班前做好责任区6S"}',"ABDE","叉车须停指定区域，不可任意停放(C错)。其余均为规范要求。"),
        (4,"multi","以下哪些违规行为会被扣绩效1000元/次？（多选）",'{"A":"仓库内吸烟","B":"穿短裤上岗","C":"叉车载人或违规登高","D":"酒后驾驶叉车","E":"擅自借出/赠送公司物资"}',"ACDE","穿短裤扣100元(B错)。其余四项均为扣1000元严重违规。"),
        (4,"multi","货物入库规范中，以下哪些操作是正确的？（多选）",'{"A":"卸货前检查货物外观，异常立即上报","B":"收货验收后直接上架，无需PDA扫码","C":"木托盘放一层，塑胶托盘放2层以上","D":"1-3层可直接上架，4层以上等高位叉车","E":"货物、标签、托盘号均需朝向通道"}',"ACDE","入库必须PDA扫码后才能转运上架(B错)。"),
        (4,"multi","以下哪些属于叉车操作违规行为？（多选）",'{"A":"下坡时倒车行驶","B":"在一二层使用高位叉车","C":"多托货物以推行形式移动","D":"车速超过8KM/H","E":"托盘离地超过30CM"}',"BCDE","下坡应倒车行驶(A是正确操作，非违规)。"),
        (4,"multi","关于货物出入库违规处罚，以下哪些说法正确？（多选）",'{"A":"客户投诉情节一般且可妥善处理：扣绩效300元","B":"导致客户停线：扣绩效1000元并承担全部经济责任","C":"内部检举未造成损失：责任人扣200元，检举人奖200元","D":"员工任何操作失误都必须经济处罚","E":"员工自行发现并及时纠正、未造成影响：仅通报批评不处罚"}',"ABCE","员工自行发现且及时纠正、未造成影响的可不处罚(D错)。"),
        (4,"judge","叉车司机可以穿露趾鞋上岗作业。",'{"A":"正确","B":"错误"}',"B","严禁穿露趾鞋上岗！着装规范明确要求安全防护。"),
        (4,"judge","每日下班前叉车司机须做好责任区6S，做到工完场净。",'{"A":"正确","B":"错误"}',"A","规范第⑥条：每日下班前做好责任区6S，工完场净。"),
        (4,"judge","下坡时叉车应正向（车头朝前）行驶以确保安全。",'{"A":"正确","B":"错误"}',"B","下坡时应倒车行驶！正向行驶属于违规，扣绩效100元/次。"),
        (4,"judge","单托500kg以下的货物可以堆叠4层以上存放。",'{"A":"正确","B":"错误"}',"A","入库规范：单托500kg以下放4层以上。"),
        (4,"judge","四级连带责任制度涉及：现场主管→副总监→安全总监→副总。",'{"A":"正确","B":"错误"}',"A","规范明确四级连带责任：现场主管——副总监——安全总监——副总。"),
    ]
    for cat, typ, q, opts, ans, analysis in data:
        qs.append({
            "id": len(qs)+1, "categoryId": cat, "type": typ,
            "content": q, "options": opts, "answer": ans,
            "analysis": analysis, "difficulty": 1, "score": 5
        })
    return qs

init()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
