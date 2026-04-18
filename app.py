import os, sqlite3, secrets, hashlib, json, time
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DATA_DIR = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', '/data')
DB_PATH  = os.path.join(DATA_DIR, 'widget.db')
os.makedirs(DATA_DIR, exist_ok=True)

# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            email     TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            plan      TEXT DEFAULT 'free',
            created   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS agents (
            id            TEXT PRIMARY KEY,
            user_id       INTEGER NOT NULL,
            name          TEXT NOT NULL,
            tagline       TEXT DEFAULT 'Ask me anything!',
            color         TEXT DEFAULT '#6366f1',
            avatar        TEXT DEFAULT '🤖',
            system_prompt TEXT DEFAULT 'You are a helpful AI assistant.',
            model         TEXT DEFAULT 'openai/gpt-4o-mini',
            api_key       TEXT NOT NULL,
            allowed_origins TEXT DEFAULT '*',
            msg_count     INTEGER DEFAULT 0,
            created       TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id  TEXT NOT NULL,
            role      TEXT NOT NULL,
            content   TEXT NOT NULL,
            session_id TEXT,
            ts        TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        CREATE TABLE IF NOT EXISTS rate_log (
            key  TEXT NOT NULL,
            ts   REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rate_log_key ON rate_log(key);
    ''')
    db.commit()
    db.close()

init_db()

# ── Auth helpers ──────────────────────────────────────────────────────────────

import bcrypt as _bcrypt

def hash_pw(pw):
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()

def check_pw(pw, stored):
    try:
        return _bcrypt.checkpw(pw.encode(), stored.encode())
    except Exception:
        return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Rate limiting ─────────────────────────────────────────────────────────────

def is_rate_limited(key, max_calls=20, window=60):
    db = get_db()
    now = time.time()
    db.execute("DELETE FROM rate_log WHERE ts < ?", (now - window,))
    count = db.execute("SELECT COUNT(*) FROM rate_log WHERE key=?", (key,)).fetchone()[0]
    if count >= max_calls:
        return True
    db.execute("INSERT INTO rate_log(key,ts) VALUES(?,?)", (key, now))
    db.commit()
    return False

# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def security_headers(res):
    res.headers['X-Content-Type-Options'] = 'nosniff'
    res.headers['X-Frame-Options'] = 'SAMEORIGIN'
    res.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return res

# ── CORS for widget ───────────────────────────────────────────────────────────

@app.after_request
def cors_headers(res):
    if request.path.startswith('/widget/') or request.path.startswith('/chat/'):
        origin = request.headers.get('Origin', '*')
        res.headers['Access-Control-Allow-Origin'] = origin
        res.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        res.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return res

# ── OpenRouter chat ───────────────────────────────────────────────────────────

import requests as _req

def call_openrouter(messages, model, api_key):
    try:
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {api_key}',
                     'Content-Type': 'application/json',
                     'HTTP-Referer': 'https://ai-agent-widget-production.up.railway.app',
                     'X-Title': 'Alexander AI Agent'},
            json={'model': model, 'messages': messages, 'max_tokens': 800},
            timeout=30
        )
        if r.status_code == 401:
            return "⚠️ Invalid API key. Go to Edit → check your OpenRouter key."
        if r.status_code == 402:
            return "⚠️ No credits on this API key. Add credits at openrouter.ai."
        if r.status_code == 400:
            err = r.json().get('error', {}).get('message', r.text[:200])
            return f"⚠️ Bad request: {err}"
        if r.status_code == 404:
            return f"⚠️ Model not found: '{model}'. Try editing your agent and using a model like 'openai/gpt-4o-mini' or 'google/gemini-flash-1.5'."
        if not r.ok:
            try:
                err = r.json().get('error', {}).get('message', r.text[:300])
            except Exception:
                err = r.text[:300]
            return f"⚠️ API error {r.status_code}: {err}"
        data = r.json()
        return data['choices'][0]['message']['content']
    except _req.exceptions.Timeout:
        return "⚠️ Request timed out. OpenRouter took too long to respond."
    except _req.exceptions.ConnectionError:
        return "⚠️ Could not reach OpenRouter. Check your internet connection."
    except Exception as e:
        app.logger.error(f'OpenRouter error: {type(e).__name__}: {e}')
        return f"⚠️ Unexpected error: {type(e).__name__}: {str(e)[:200]}"

# ── Public pages ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/old-index')
def old_index():
    return render_template('index.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/health')
def health():
    try:
        db = get_db()
        db.execute('SELECT 1')
        return jsonify({'status': 'ok', 'db': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'db': str(e)}), 500

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Email and password required.', 'error')
            return render_template('signup.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('signup.html')
        db = get_db()
        if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
            flash('Email already registered.', 'error')
            return render_template('signup.html')
        db.execute('INSERT INTO users(email,password) VALUES(?,?)',
                   (email, hash_pw(password)))
        db.commit()
        user = db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        session['user_id'] = user['id']
        session['email']   = email
        flash('Welcome to Alexander AI Agent! 🎉', 'success')
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        ip = request.remote_addr
        if is_rate_limited(f'login:{ip}', max_calls=10, window=60):
            flash('Too many login attempts. Try again in a minute.', 'error')
            return render_template('login.html')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not user or not check_pw(password, user['password']):
            flash('Invalid email or password.', 'error')
            return render_template('login.html')
        session['user_id'] = user['id']
        session['email']   = user['email']
        session['plan']    = user['plan']
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pw  = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
        if not check_pw(current, user['password']):
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html')
        if new_pw != confirm:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        if len(new_pw) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('change_password.html')
        db.execute('UPDATE users SET password=? WHERE id=?',
                   (hash_pw(new_pw), session['user_id']))
        db.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    agents = db.execute(
        'SELECT * FROM agents WHERE user_id=? ORDER BY created DESC',
        (session['user_id'],)
    ).fetchall()
    plan = db.execute('SELECT plan FROM users WHERE id=?', (session['user_id'],)).fetchone()['plan']
    return render_template('dashboard.html', agents=agents, plan=plan)

# ── Agent CRUD ────────────────────────────────────────────────────────────────

@app.route('/agent/new', methods=['GET', 'POST'])
@login_required
def new_agent():
    db = get_db()
    plan = db.execute('SELECT plan FROM users WHERE id=?', (session['user_id'],)).fetchone()['plan']
    agent_count = db.execute('SELECT COUNT(*) FROM agents WHERE user_id=?', (session['user_id'],)).fetchone()[0]

    if plan == 'free' and agent_count >= 1:
        flash('Free plan allows 1 agent. Upgrade to create more.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name          = request.form.get('name', '').strip()
        tagline       = request.form.get('tagline', 'Ask me anything!').strip()
        color         = request.form.get('color', '#6366f1')
        avatar        = request.form.get('avatar', '🤖').strip()
        system_prompt = request.form.get('system_prompt', 'You are a helpful AI assistant.').strip()
        model         = request.form.get('model', 'openai/gpt-4o-mini')
        api_key       = request.form.get('api_key', '').strip()
        origins       = request.form.get('allowed_origins', '*').strip()

        if not name:
            flash('Agent name is required.', 'error')
            return render_template('agent_form.html', agent=None)
        if not api_key:
            flash('OpenRouter API key is required.', 'error')
            return render_template('agent_form.html', agent=None)

        agent_id = secrets.token_urlsafe(16)
        db.execute('''INSERT INTO agents
            (id,user_id,name,tagline,color,avatar,system_prompt,model,api_key,allowed_origins)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (agent_id, session['user_id'], name, tagline, color, avatar,
             system_prompt, model, api_key, origins))
        db.commit()
        flash(f'Agent "{name}" created! 🎉', 'success')
        return redirect(url_for('agent_detail', agent_id=agent_id))

    return render_template('agent_form.html', agent=None)

@app.route('/agent/<agent_id>')
@login_required
def agent_detail(agent_id):
    db = get_db()
    agent = db.execute(
        'SELECT * FROM agents WHERE id=? AND user_id=?',
        (agent_id, session['user_id'])
    ).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))
    base_url = request.host_url.rstrip('/')
    return render_template('agent_detail.html', agent=agent, base_url=base_url)

@app.route('/agent/<agent_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_agent(agent_id):
    db = get_db()
    agent = db.execute(
        'SELECT * FROM agents WHERE id=? AND user_id=?',
        (agent_id, session['user_id'])
    ).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name          = request.form.get('name', '').strip()
        tagline       = request.form.get('tagline', '').strip()
        color         = request.form.get('color', '#6366f1')
        avatar        = request.form.get('avatar', '🤖').strip()
        system_prompt = request.form.get('system_prompt', '').strip()
        model         = request.form.get('model', 'openai/gpt-4o-mini')
        api_key       = request.form.get('api_key', '').strip() or agent['api_key']
        origins       = request.form.get('allowed_origins', '*').strip()

        db.execute('''UPDATE agents SET
            name=?,tagline=?,color=?,avatar=?,system_prompt=?,model=?,api_key=?,allowed_origins=?
            WHERE id=? AND user_id=?''',
            (name, tagline, color, avatar, system_prompt, model, api_key, origins,
             agent_id, session['user_id']))
        db.commit()
        flash('Agent updated! ✅', 'success')
        return redirect(url_for('agent_detail', agent_id=agent_id))

    return render_template('agent_form.html', agent=agent)

@app.route('/agent/<agent_id>/delete', methods=['POST'])
@login_required
def delete_agent(agent_id):
    db = get_db()
    db.execute('DELETE FROM agents WHERE id=? AND user_id=?',
               (agent_id, session['user_id']))
    db.commit()
    flash('Agent deleted.', 'success')
    return redirect(url_for('dashboard'))

# ── Widget loader (JS) ────────────────────────────────────────────────────────

@app.route('/widget/<agent_id>.js')
def widget_js(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        return 'console.error("Alexander AI Agent: invalid agent ID");', 404, \
               {'Content-Type': 'application/javascript'}

    base_url = request.host_url.rstrip('/').replace('http://', 'https://')
    js = render_template('widget.js',
        agent=dict(agent), base_url=base_url,
        color=agent['color'], avatar=agent['avatar'],
        name=agent['name'], tagline=agent['tagline'])
    return js, 200, {'Content-Type': 'application/javascript',
                     'Cache-Control': 'public, max-age=300'}

# ── Chat API (used by widget) ─────────────────────────────────────────────────

@app.route('/chat/<agent_id>', methods=['POST', 'OPTIONS'])
def chat(agent_id):
    if request.method == 'OPTIONS':
        return '', 204

    ip = request.remote_addr
    if is_rate_limited(f'chat:{agent_id}:{ip}', max_calls=30, window=60):
        return jsonify({'error': 'Rate limit exceeded. Please wait a moment.'}), 429

    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404

    data       = request.get_json(silent=True) or {}
    user_msg   = (data.get('message') or '').strip()
    history    = data.get('history') or []
    session_id = data.get('session_id', '')

    if not user_msg:
        return jsonify({'error': 'Message required'}), 400
    if len(user_msg) > 2000:
        return jsonify({'error': 'Message too long (max 2000 chars)'}), 400

    messages = [{'role': 'system', 'content': agent['system_prompt']}]
    for h in history[-10:]:  # last 10 turns for context
        if h.get('role') in ('user', 'assistant') and h.get('content'):
            messages.append({'role': h['role'], 'content': h['content'][:1000]})
    messages.append({'role': 'user', 'content': user_msg})

    reply = call_openrouter(messages, agent['model'], agent['api_key'])

    # Log message + increment counter
    db.execute('INSERT INTO messages(agent_id,role,content,session_id) VALUES(?,?,?,?)',
               (agent_id, 'user', user_msg, session_id))
    db.execute('INSERT INTO messages(agent_id,role,content,session_id) VALUES(?,?,?,?)',
               (agent_id, 'assistant', reply, session_id))
    db.execute('UPDATE agents SET msg_count=msg_count+1 WHERE id=?', (agent_id,))
    db.commit()

    return jsonify({'reply': reply})

# ── Agent preview (live demo) ─────────────────────────────────────────────────

@app.route('/preview/<agent_id>')
def preview(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('index'))
    return render_template('preview.html', agent=dict(agent))

# ── Analytics ─────────────────────────────────────────────────────────────────

@app.route('/agent/<agent_id>/analytics')
@login_required
def agent_analytics(agent_id):
    db = get_db()
    agent = db.execute(
        'SELECT * FROM agents WHERE id=? AND user_id=?',
        (agent_id, session['user_id'])
    ).fetchone()
    if not agent:
        return redirect(url_for('dashboard'))

    msgs = db.execute(
        'SELECT * FROM messages WHERE agent_id=? ORDER BY ts DESC LIMIT 100',
        (agent_id,)
    ).fetchall()
    return render_template('analytics.html', agent=agent, messages=msgs)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
