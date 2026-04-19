import os, sqlite3, secrets, hashlib, json, time, threading, datetime
import urllib.request
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g)
import stripe

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PK       = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WH_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')

# Price IDs — set these as Railway env vars after creating products in Stripe
STRIPE_PRICE_PRO      = os.environ.get('STRIPE_PRICE_PRO', '')       # $19/mo
STRIPE_PRICE_BUSINESS = os.environ.get('STRIPE_PRICE_BUSINESS', '')  # $49/mo

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
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            email                  TEXT UNIQUE NOT NULL,
            password               TEXT NOT NULL,
            plan                   TEXT DEFAULT 'free',
            plan_status            TEXT DEFAULT 'active',
            stripe_customer_id     TEXT,
            stripe_subscription_id TEXT,
            is_admin               INTEGER DEFAULT 0,
            created                TEXT DEFAULT (datetime('now'))
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
            training_notes TEXT DEFAULT '',
            trained_by    TEXT DEFAULT '',
            trained_at    TEXT DEFAULT '',
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
        CREATE TABLE IF NOT EXISTS knowledge_base (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            type     TEXT NOT NULL DEFAULT 'text',
            title    TEXT DEFAULT '',
            content  TEXT NOT NULL,
            source   TEXT DEFAULT '',
            created  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        CREATE INDEX IF NOT EXISTS idx_kb_agent ON knowledge_base(agent_id);
        CREATE TABLE IF NOT EXISTS session_memory (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id      TEXT NOT NULL,
            session_id    TEXT NOT NULL,
            summary       TEXT NOT NULL DEFAULT '',
            message_count INTEGER DEFAULT 0,
            last_seen     TEXT DEFAULT (datetime('now')),
            UNIQUE(agent_id, session_id),
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        CREATE INDEX IF NOT EXISTS idx_memory_agent_session ON session_memory(agent_id, session_id);
        CREATE TABLE IF NOT EXISTS tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            priority    TEXT NOT NULL DEFAULT 'normal',
            subject     TEXT NOT NULL,
            description TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'open',
            admin_reply TEXT DEFAULT '',
            replied_at  TEXT DEFAULT NULL,
            created     TEXT DEFAULT (datetime('now')),
            updated     TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_tickets_user ON tickets(user_id);
        CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
    ''')
    db.commit()
    db.close()

init_db()

def migrate_model_names():
    """Fix any legacy/broken model names in the database on startup."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        agents = db.execute('SELECT id, model FROM agents').fetchall()
        for agent in agents:
            fixed = normalize_model(agent['model'])
            if fixed != agent['model']:
                app.logger.info(f"Migrating model: {agent['model']} -> {fixed} (agent {agent['id']})")
                db.execute('UPDATE agents SET model=? WHERE id=?', (fixed, agent['id']))
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f'Model migration error: {e}')

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

# ── Model name normalizer ────────────────────────────────────────────────────

MODEL_ALIASES = {
    # Gemini
    'gemini-flash-1.5':                      'google/gemini-flash-1.5',
    'gemini-pro':                            'google/gemini-pro',
    'gemini-1.5-pro':                        'google/gemini-pro-1.5',
    'gemini-2.0-flash':                      'google/gemini-2.0-flash-001',
    'gemini-flash-2.0':                      'google/gemini-2.0-flash-001',
    # Claude
    'claude-3-haiku':                        'anthropic/claude-3.5-haiku',
    'claude-3.5-haiku':                      'anthropic/claude-3.5-haiku',
    'claude-3.5-sonnet':                     'anthropic/claude-sonnet-4-5',
    'claude-3-sonnet':                       'anthropic/claude-sonnet-4-5',
    'claude-3-opus':                         'anthropic/claude-3-opus',
    'anthropic/claude-3-haiku':              'anthropic/claude-3.5-haiku',
    'anthropic/claude-3.5-sonnet':           'anthropic/claude-sonnet-4-5',
    # GPT
    'gpt-4o':                                'openai/gpt-4o',
    'gpt-4o-mini':                           'openai/gpt-4o-mini',
    'gpt-4':                                 'openai/gpt-4',
    'gpt-3.5-turbo':                         'openai/gpt-3.5-turbo',
    # Llama — old free tier IDs that are now 404
    'meta-llama/llama-3.1-8b-instruct:free': 'meta-llama/llama-3.3-70b-instruct',
    'llama-3.1-8b':                          'meta-llama/llama-3.3-70b-instruct',
    'llama-3.1-8b-instruct':                 'meta-llama/llama-3.3-70b-instruct',
    'llama-3.3-70b':                         'meta-llama/llama-3.3-70b-instruct',
    # Mistral
    'mistral-7b':                            'mistralai/mistral-7b-instruct',
    'mixtral-8x7b':                          'mistralai/mixtral-8x7b-instruct',
}

def normalize_model(model):
    """Fix common shorthand model names to their full OpenRouter IDs."""
    if not model:
        return 'openai/gpt-4o-mini'
    return MODEL_ALIASES.get(model, MODEL_ALIASES.get(model.lower(), model))

migrate_model_names()

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
        confirm  = request.form.get('confirm_password', '')
        if not email or not password:
            flash('Email and password required.', 'error')
            return render_template('signup.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('signup.html')
        if password != confirm:
            flash('Passwords do not match.', 'error')
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
        session['user_id']  = user['id']
        session['email']    = user['email']
        session['plan']     = user['plan']
        session['is_admin'] = bool(user['is_admin'])
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ── Password reset ────────────────────────────────────────────────────────────

# In-memory token store: {token: {email, expires}}
# For production, move this to the DB. Fine for now.
_reset_tokens = {}

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        # Always show success — don't reveal if email exists (security)
        if user:
            token = secrets.token_urlsafe(32)
            _reset_tokens[token] = {
                'email': email,
                'expires': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            reset_url = f"{request.host_url.rstrip('/')}/reset-password/{token}"
            app.logger.info(f'Password reset requested for {email}: {reset_url}')
            # TODO: send email when SMTP is configured
            # For now, flash the link so Jay can test (remove in production)
            flash(f'Reset link (dev mode — add SMTP to send email): {reset_url}', 'success')
        else:
            flash('If that email exists, a reset link has been sent.', 'success')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    data = _reset_tokens.get(token)
    if not data or datetime.datetime.utcnow() > data['expires']:
        flash('This reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        db = get_db()
        db.execute('UPDATE users SET password=? WHERE email=?',
                   (hash_pw(password), data['email']))
        db.commit()
        del _reset_tokens[token]
        flash('Password reset successfully! Please sign in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

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
    base_url = ('https://' + request.host).rstrip('/')
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

    base_url = ('https://' + request.host).rstrip('/')
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

    # Normalize model name (fix shorthand like 'gemini-flash-1.5' -> 'google/gemini-flash-1.5')
    model = normalize_model(agent['model'])
    if model != agent['model']:
        db.execute('UPDATE agents SET model=? WHERE id=?', (model, agent_id))
        db.commit()

    # ── Inject Knowledge Base into system prompt ──
    kb_entries = db.execute(
        'SELECT title, content FROM knowledge_base WHERE agent_id=? ORDER BY created ASC',
        (agent_id,)
    ).fetchall()
    if kb_entries:
        kb_text = '\n\n'.join(
            f"[{e['title'] or 'Knowledge'}]\n{e['content']}" for e in kb_entries
        )
        system_content = agent['system_prompt'] + f'\n\n---\nKNOWLEDGE BASE:\n{kb_text[:6000]}\n---'
    else:
        system_content = agent['system_prompt']

    # ── Inject visitor memory ──
    if session_id and session_id != 'dashboard-test':
        mem = db.execute(
            'SELECT summary, message_count FROM session_memory WHERE agent_id=? AND session_id=?',
            (agent_id, session_id)
        ).fetchone()
        if mem and mem['summary']:
            system_content += f'\n\n---\nVISITOR MEMORY (returning user):\n{mem["summary"]}\n---'

    messages = [{'role': 'system', 'content': system_content}]
    for h in history[-10:]:
        if h.get('role') in ('user', 'assistant') and h.get('content'):
            messages.append({'role': h['role'], 'content': h['content'][:1000]})
    messages.append({'role': 'user', 'content': user_msg})

    reply = call_openrouter(messages, model, agent['api_key'])

    # Log message + increment counter
    db.execute('INSERT INTO messages(agent_id,role,content,session_id) VALUES(?,?,?,?)',
               (agent_id, 'user', user_msg, session_id))
    db.execute('INSERT INTO messages(agent_id,role,content,session_id) VALUES(?,?,?,?)',
               (agent_id, 'assistant', reply, session_id))
    db.execute('UPDATE agents SET msg_count=msg_count+1 WHERE id=?', (agent_id,))

    # ── Update visitor memory ──
    if session_id and session_id != 'dashboard-test' and len(session_id) > 4:
        existing_mem = db.execute(
            'SELECT id, message_count, summary FROM session_memory WHERE agent_id=? AND session_id=?',
            (agent_id, session_id)
        ).fetchone()
        new_count = (existing_mem['message_count'] if existing_mem else 0) + 1
        # Build a simple rolling summary every 5 exchanges
        summary = existing_mem['summary'] if existing_mem else ''
        if new_count % 5 == 0 or not summary:
            recent_msgs = db.execute(
                'SELECT role, content FROM messages WHERE agent_id=? AND session_id=? ORDER BY ts DESC LIMIT 10',
                (agent_id, session_id)
            ).fetchall()
            if recent_msgs:
                convo = '\n'.join(f"{m['role'].upper()}: {m['content'][:200]}" for m in reversed(recent_msgs))
                summary_prompt = [
                    {'role': 'system', 'content': 'Summarize this conversation in 2-3 sentences. Focus on what the visitor asked about and any important details like their name, needs, or preferences. Be concise.'},
                    {'role': 'user', 'content': convo}
                ]
                new_summary = call_openrouter(summary_prompt, model, agent['api_key'])
                if not new_summary.startswith('⚠️'):
                    summary = new_summary
        if existing_mem:
            db.execute(
                'UPDATE session_memory SET summary=?, message_count=?, last_seen=datetime(\'now\') WHERE id=?',
                (summary, new_count, existing_mem['id'])
            )
        else:
            db.execute(
                'INSERT INTO session_memory(agent_id, session_id, summary, message_count) VALUES(?,?,?,?)',
                (agent_id, session_id, summary, new_count)
            )

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

# ── Knowledge Base ──────────────────────────────────────────────────────────────

def agent_owned(agent_id):
    """Return agent row if it belongs to logged-in user, else None."""
    db = get_db()
    return db.execute(
        'SELECT * FROM agents WHERE id=? AND user_id=?',
        (agent_id, session['user_id'])
    ).fetchone()

@app.route('/agent/<agent_id>/kb')
@login_required
def kb_page(agent_id):
    agent = agent_owned(agent_id)
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))
    db = get_db()
    entries = db.execute(
        'SELECT * FROM knowledge_base WHERE agent_id=? ORDER BY created DESC',
        (agent_id,)
    ).fetchall()
    memories = db.execute(
        'SELECT * FROM session_memory WHERE agent_id=? ORDER BY last_seen DESC',
        (agent_id,)
    ).fetchall()
    total_chars = sum(len(e['content']) for e in entries)
    return render_template('knowledge_base.html',
        agent=agent, entries=entries, memories=memories,
        total_chars=total_chars, memory_count=len(memories))

@app.route('/agent/<agent_id>/kb/add', methods=['POST'])
@login_required
def kb_add(agent_id):
    agent = agent_owned(agent_id)
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))

    kb_type = request.form.get('type', 'text')
    title   = request.form.get('title', '').strip()[:200]
    db = get_db()

    if kb_type == 'text':
        content = request.form.get('content', '').strip()
        if not content:
            flash('Content cannot be empty.', 'error')
            return redirect(url_for('kb_page', agent_id=agent_id))
        content = content[:10000]
        db.execute(
            'INSERT INTO knowledge_base(agent_id,type,title,content,source) VALUES(?,?,?,?,?)',
            (agent_id, 'text', title, content, '')
        )
        db.commit()
        flash('Knowledge added! ✅', 'success')

    elif kb_type == 'url':
        url = request.form.get('url', '').strip()
        if not url:
            flash('URL is required.', 'error')
            return redirect(url_for('kb_page', agent_id=agent_id))
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; AlexanderAI-KB-Scraper/1.0)'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
            # Simple HTML stripping
            import re
            html = raw.decode('utf-8', errors='replace')
            # Remove scripts, styles, tags
            html = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r'<[^>]+>', ' ', html)
            html = re.sub(r'&nbsp;', ' ', html)
            html = re.sub(r'&amp;', '&', html)
            html = re.sub(r'&lt;', '<', html)
            html = re.sub(r'&gt;', '>', html)
            html = re.sub(r'[ \t]+', ' ', html)
            html = re.sub(r'\n{3,}', '\n\n', html)
            content = html.strip()[:10000]
            if not title:
                title = url[:100]
            db.execute(
                'INSERT INTO knowledge_base(agent_id,type,title,content,source) VALUES(?,?,?,?,?)',
                (agent_id, 'url', title, content, url)
            )
            db.commit()
            flash(f'URL scraped and saved! ({len(content)} chars) ✅', 'success')
        except Exception as e:
            flash(f'Could not scrape URL: {str(e)[:200]}', 'error')

    elif kb_type == 'file':
        f = request.files.get('file')
        if not f or not f.filename:
            flash('No file selected.', 'error')
            return redirect(url_for('kb_page', agent_id=agent_id))
        if not f.filename.lower().endswith('.txt'):
            flash('Only .txt files are supported.', 'error')
            return redirect(url_for('kb_page', agent_id=agent_id))
        content = f.read(512 * 1024).decode('utf-8', errors='replace').strip()[:10000]
        if not content:
            flash('File appears to be empty.', 'error')
            return redirect(url_for('kb_page', agent_id=agent_id))
        if not title:
            title = f.filename
        db.execute(
            'INSERT INTO knowledge_base(agent_id,type,title,content,source) VALUES(?,?,?,?,?)',
            (agent_id, 'file', title, content, f.filename)
        )
        db.commit()
        flash(f'File uploaded! ({len(content)} chars) ✅', 'success')

    return redirect(url_for('kb_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/kb/delete/<int:entry_id>', methods=['POST'])
@login_required
def kb_delete(agent_id, entry_id):
    agent = agent_owned(agent_id)
    if not agent:
        return redirect(url_for('dashboard'))
    db = get_db()
    db.execute('DELETE FROM knowledge_base WHERE id=? AND agent_id=?', (entry_id, agent_id))
    db.commit()
    flash('Entry deleted.', 'success')
    return redirect(url_for('kb_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/kb/clear', methods=['POST'])
@login_required
def kb_clear(agent_id):
    agent = agent_owned(agent_id)
    if not agent:
        return redirect(url_for('dashboard'))
    db = get_db()
    db.execute('DELETE FROM knowledge_base WHERE agent_id=?', (agent_id,))
    db.commit()
    flash('Knowledge base cleared.', 'success')
    return redirect(url_for('kb_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/memory/delete/<int:mem_id>', methods=['POST'])
@login_required
def memory_delete(agent_id, mem_id):
    agent = agent_owned(agent_id)
    if not agent:
        return redirect(url_for('dashboard'))
    db = get_db()
    db.execute('DELETE FROM session_memory WHERE id=? AND agent_id=?', (mem_id, agent_id))
    db.commit()
    flash('Memory deleted.', 'success')
    return redirect(url_for('kb_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/memory/clear', methods=['POST'])
@login_required
def memory_clear(agent_id):
    agent = agent_owned(agent_id)
    if not agent:
        return redirect(url_for('dashboard'))
    db = get_db()
    db.execute('DELETE FROM session_memory WHERE agent_id=?', (agent_id,))
    db.commit()
    flash('All visitor memories cleared.', 'success')
    return redirect(url_for('kb_page', agent_id=agent_id))

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

# ── Admin bootstrap ───────────────────────────────────────────────────────

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'alexanderjay70@gmail.com')

def bootstrap_admin():
    """Ensure the admin user exists and has admin + pro plan."""
    try:
        db = sqlite3.connect(DB_PATH)
        # Add is_admin column if it doesn't exist yet (migration)
        try:
            db.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
            db.commit()
        except Exception:
            pass  # Column already exists
        db.execute(
            'UPDATE users SET is_admin=1, plan=? WHERE email=?',
            ('admin', ADMIN_EMAIL)
        )
        db.commit()
        affected = db.execute('SELECT changes()').fetchone()[0]
        if affected:
            app.logger.info(f'Admin privileges granted to {ADMIN_EMAIL}')
        db.close()
    except Exception as e:
        app.logger.error(f'Admin bootstrap error: {e}')

bootstrap_admin()

# ── Stripe DB migrations ───────────────────────────────────────────────────
def run_stripe_migrations():
    """Add Stripe columns to users table if they don't exist."""
    try:
        db = sqlite3.connect(DB_PATH)
        cols = {r[1] for r in db.execute('PRAGMA table_info(users)').fetchall()}
        for col, defn in [
            ('plan_status',            'TEXT DEFAULT \'active\''),
            ('stripe_customer_id',     'TEXT'),
            ('stripe_subscription_id', 'TEXT'),
        ]:
            if col not in cols:
                db.execute(f'ALTER TABLE users ADD COLUMN {col} {defn}')
                app.logger.info(f'Migration: added column {col}')
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f'Stripe migration error: {e}')

run_stripe_migrations()

# ── Stripe helpers ─────────────────────────────────────────────────────────
PLAN_PRICES = {'pro': STRIPE_PRICE_PRO, 'business': STRIPE_PRICE_BUSINESS}
PLAN_HIERARCHY = {'free': 0, 'pro': 1, 'business': 2, 'admin': 9}

@app.route('/billing/checkout/<plan>')
def billing_checkout(plan):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if plan not in PLAN_PRICES or not PLAN_PRICES[plan]:
        flash('Invalid plan or Stripe not configured.', 'error')
        return redirect(url_for('pricing'))
    try:
        checkout = stripe.checkout.Session.create(
            customer_email=session.get('email'),
            payment_method_types=['card'],
            line_items=[{'price': PLAN_PRICES[plan], 'quantity': 1}],
            mode='subscription',
            success_url=request.host_url + 'billing/success',
            cancel_url=request.host_url + 'pricing',
            metadata={'user_id': str(session['user_id']), 'plan': plan},
        )
        return redirect(checkout.url)
    except Exception as e:
        app.logger.error(f'Stripe checkout error: {e}')
        flash('Payment error. Please try again.', 'error')
        return redirect(url_for('pricing'))

@app.route('/billing/success')
def billing_success():
    flash('🎉 Payment successful! Your plan will activate within seconds.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/billing/portal')
def billing_portal():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT stripe_customer_id FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if not user or not user['stripe_customer_id']:
        flash('No active subscription found.', 'error')
        return redirect(url_for('pricing'))
    try:
        portal = stripe.billing_portal.Session.create(
            customer=user['stripe_customer_id'],
            return_url=request.host_url + 'dashboard',
        )
        return redirect(portal.url)
    except Exception as e:
        flash('Could not open billing portal. Please contact support.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig     = request.headers.get('Stripe-Signature', '')
    if not STRIPE_WH_SECRET:
        return '', 200
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WH_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        return 'Invalid signature', 400
    threading.Thread(target=_handle_stripe_event, args=(event,), daemon=True).start()
    return '', 200

def _handle_stripe_event(event):
    etype = event['type']
    data  = event['data']['object']
    db    = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        if etype == 'checkout.session.completed':
            user_id = data['metadata'].get('user_id')
            plan    = data['metadata'].get('plan', 'pro')
            cus_id  = data.get('customer')
            sub_id  = data.get('subscription')
            if user_id:
                db.execute(
                    'UPDATE users SET plan=?, plan_status=\'active\', stripe_customer_id=?, stripe_subscription_id=? WHERE id=?',
                    (plan, cus_id, sub_id, int(user_id))
                )
                app.logger.info(f'User {user_id} upgraded to {plan}')
        elif etype == 'customer.subscription.updated':
            sub_id = data['id']
            status = data['status']
            db.execute('UPDATE users SET plan_status=? WHERE stripe_subscription_id=?', (status, sub_id))
        elif etype == 'customer.subscription.deleted':
            sub_id = data['id']
            db.execute(
                'UPDATE users SET plan=\'free\', plan_status=\'canceled\', stripe_subscription_id=NULL WHERE stripe_subscription_id=?',
                (sub_id,)
            )
            app.logger.info(f'Subscription {sub_id} canceled — downgraded to free')
        elif etype == 'invoice.payment_failed':
            cus_id = data.get('customer')
            if cus_id:
                db.execute('UPDATE users SET plan_status=\'past_due\' WHERE stripe_customer_id=?', (cus_id,))
        db.commit()
    except Exception as e:
        app.logger.error(f'Webhook handler error: {e}')
    finally:
        db.close()

# ── Admin required decorator ───────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id=?', (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


@app.route('/tickets')
@login_required
def tickets_page():
    db = get_db()
    t_list = db.execute(
        "SELECT * FROM tickets WHERE user_id=? ORDER BY CASE priority WHEN 'emergency' THEN 1 WHEN 'urgent' THEN 2 ELSE 3 END, created DESC",
        (session['user_id'],)
    ).fetchall()
    return render_template('tickets.html', tickets=t_list)


@app.route('/tickets/new', methods=['POST'])
@login_required
def tickets_new():
    priority    = request.form.get('priority', 'normal')
    subject     = request.form.get('subject', '').strip()[:200]
    description = request.form.get('description', '').strip()[:5000]
    if priority not in ('normal', 'urgent', 'emergency'):
        priority = 'normal'
    if not subject or not description:
        flash('Subject and description are required.', 'error')
        return redirect(url_for('tickets_page'))
    db = get_db()
    db.execute(
        'INSERT INTO tickets(user_id, priority, subject, description) VALUES(?,?,?,?)',
        (session['user_id'], priority, subject, description)
    )
    db.commit()
    sla = {'emergency': '1 hour', 'urgent': '4 hours', 'normal': '24 hours'}[priority]
    flash(f"Ticket submitted! We'll respond within {sla}.", 'success')
    return redirect(url_for('tickets_page'))


@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    db = get_db()
    t_list = db.execute('''
        SELECT t.*, u.email as user_email
        FROM tickets t JOIN users u ON t.user_id = u.id
        ORDER BY
          CASE t.priority WHEN 'emergency' THEN 1 WHEN 'urgent' THEN 2 ELSE 3 END,
          CASE t.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'resolved' THEN 3 ELSE 4 END,
          t.created DESC
    ''').fetchall()
    stats = {
        'total':     db.execute('SELECT COUNT(*) FROM tickets').fetchone()[0],
        'open':      db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        'emergency': db.execute("SELECT COUNT(*) FROM tickets WHERE priority='emergency' AND status NOT IN ('resolved','closed')").fetchone()[0],
        'urgent':    db.execute("SELECT COUNT(*) FROM tickets WHERE priority='urgent' AND status NOT IN ('resolved','closed')").fetchone()[0],
    }
    return render_template('admin_tickets.html', tickets=t_list, stats=stats)


@app.route('/admin/tickets/<int:ticket_id>/reply', methods=['POST'])
@admin_required
def admin_ticket_reply(ticket_id):
    admin_reply = request.form.get('admin_reply', '').strip()
    status      = request.form.get('status', 'open')
    if status not in ('open', 'in_progress', 'resolved', 'closed'):
        status = 'open'
    db = get_db()
    db.execute(
        "UPDATE tickets SET admin_reply=?, status=?, replied_at=datetime('now'), updated=datetime('now') WHERE id=?",
        (admin_reply, status, ticket_id)
    )
    db.commit()
    flash('Ticket updated.', 'success')
    return redirect(url_for('admin_tickets'))

# ── Admin panel ───────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    users  = db.execute('SELECT u.*, (SELECT COUNT(*) FROM agents a WHERE a.user_id=u.id) as agent_count, (SELECT COUNT(*) FROM messages m JOIN agents a ON m.agent_id=a.id WHERE a.user_id=u.id) as msg_count FROM users u ORDER BY u.created DESC').fetchall()
    agents = db.execute('SELECT a.*, u.email FROM agents a JOIN users u ON a.user_id=u.id ORDER BY a.created DESC').fetchall()
    stats  = {
        'users':    db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'agents':   db.execute('SELECT COUNT(*) FROM agents').fetchone()[0],
        'messages': db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],
        'pro_users': db.execute("SELECT COUNT(*) FROM users WHERE plan='pro'").fetchone()[0],
    }
    ticket_stats = {
        'open':        db.execute("SELECT COUNT(*) FROM tickets WHERE status NOT IN ('resolved','closed')").fetchone()[0],
        'emergency':   db.execute("SELECT COUNT(*) FROM tickets WHERE priority='emergency' AND status NOT IN ('resolved','closed')").fetchone()[0],
        'urgent':      db.execute("SELECT COUNT(*) FROM tickets WHERE priority='urgent' AND status NOT IN ('resolved','closed')").fetchone()[0],
        'normal_open': db.execute("SELECT COUNT(*) FROM tickets WHERE priority='normal' AND status NOT IN ('resolved','closed')").fetchone()[0],
    }
    recent_tickets = db.execute('''
        SELECT t.subject, t.priority, t.created, u.email as user_email
        FROM tickets t JOIN users u ON t.user_id=u.id
        WHERE t.status NOT IN ('resolved','closed')
        ORDER BY CASE t.priority WHEN 'emergency' THEN 1 WHEN 'urgent' THEN 2 ELSE 3 END, t.created ASC
        LIMIT 5
    ''').fetchall()
    return render_template('admin.html', users=users, agents=agents, stats=stats,
                           ticket_stats=ticket_stats, recent_tickets=recent_tickets)

@app.route('/admin/user/<int:user_id>/plan', methods=['POST'])
@admin_required
def admin_set_plan(user_id):
    plan = request.form.get('plan', 'free')
    if plan not in ('free', 'pro', 'business', 'admin'):
        flash('Invalid plan.', 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    db.execute('UPDATE users SET plan=? WHERE id=?', (plan, user_id))
    db.commit()
    flash(f'Plan updated to {plan}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    # Don't delete yourself
    if user_id == session['user_id']:
        flash('Cannot delete your own account.', 'error')
        return redirect(url_for('admin_panel'))
    db.execute('DELETE FROM messages WHERE agent_id IN (SELECT id FROM agents WHERE user_id=?)', (user_id,))
    db.execute('DELETE FROM agents WHERE user_id=?', (user_id,))
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    if user_id == session['user_id']:
        flash('Cannot change your own admin status.', 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    current = db.execute('SELECT is_admin FROM users WHERE id=?', (user_id,)).fetchone()
    new_val = 0 if current and current['is_admin'] else 1
    db.execute('UPDATE users SET is_admin=? WHERE id=?', (new_val, user_id))
    db.commit()
    flash(f'Admin status {"granted" if new_val else "revoked"}.', 'success')
    return redirect(url_for('admin_panel'))

# ── Admin: Agent Trainer ─────────────────────────────────────────────────

def migrate_training_columns():
    """Add training columns to agents table if they don't exist."""
    try:
        db = sqlite3.connect(DB_PATH)
        for col, default in [('training_notes', ''), ('trained_by', ''), ('trained_at', '')]:
            try:
                db.execute(f"ALTER TABLE agents ADD COLUMN {col} TEXT DEFAULT '{default}'")
            except Exception:
                pass
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f'Training migration error: {e}')

migrate_training_columns()

@app.route('/admin/agent/<agent_id>/train', methods=['GET'])
@admin_required
def admin_train_agent(agent_id):
    db = get_db()
    agent = db.execute(
        'SELECT a.*, u.email as owner_email FROM agents a JOIN users u ON a.user_id=u.id WHERE a.id=?',
        (agent_id,)
    ).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('admin_panel'))
    # Recent conversation history for context
    recent_msgs = db.execute(
        'SELECT * FROM messages WHERE agent_id=? ORDER BY ts DESC LIMIT 50',
        (agent_id,)
    ).fetchall()
    return render_template('admin_train.html', agent=dict(agent), recent_msgs=recent_msgs)

@app.route('/admin/agent/<agent_id>/train/save', methods=['POST'])
@admin_required
def admin_train_save(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('admin_panel'))

    name          = request.form.get('name', agent['name']).strip()
    tagline       = request.form.get('tagline', agent['tagline']).strip()
    system_prompt = request.form.get('system_prompt', '').strip()
    model         = request.form.get('model', agent['model'])
    color         = request.form.get('color', agent['color'])
    avatar        = request.form.get('avatar', agent['avatar']).strip()
    training_notes = request.form.get('training_notes', '').strip()
    # Only update api_key if a new one was provided
    new_key = request.form.get('api_key', '').strip()
    api_key = new_key if new_key else agent['api_key']

    model = normalize_model(model)

    import datetime as _dt
    now = _dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    db.execute('''UPDATE agents SET
        name=?, tagline=?, system_prompt=?, model=?, color=?, avatar=?,
        training_notes=?, trained_by=?, trained_at=?, api_key=?
        WHERE id=?''',
        (name, tagline, system_prompt, model, color, avatar,
         training_notes, session['email'], now, api_key, agent_id))
    db.commit()
    flash(f'Agent "{name}" trained and saved successfully! ✅', 'success')
    return redirect(url_for('admin_train_agent', agent_id=agent_id))

@app.route('/admin/agent/<agent_id>/train/chat', methods=['POST'])
@admin_required
def admin_train_chat(agent_id):
    """Admin test chat — uses agent config but doesn't log to messages table."""
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404

    data = request.get_json(silent=True) or {}
    user_msg = (data.get('message') or '').strip()
    history  = data.get('history') or []
    # Allow testing with a custom system prompt (unsaved draft)
    test_prompt = data.get('test_prompt') or agent['system_prompt']
    test_model  = normalize_model(data.get('test_model') or agent['model'])

    if not user_msg:
        return jsonify({'error': 'Message required'}), 400

    messages = [{'role': 'system', 'content': test_prompt}]
    for h in history[-10:]:
        if h.get('role') in ('user', 'assistant') and h.get('content'):
            messages.append({'role': h['role'], 'content': h['content'][:1000]})
    messages.append({'role': 'user', 'content': user_msg})

    reply = call_openrouter(messages, test_model, agent['api_key'])
    return jsonify({'reply': reply})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
