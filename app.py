import os, sqlite3, secrets, hashlib, json, time, threading, datetime
import urllib.request, urllib.error
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g)
import stripe

# ── KYS Integration — fetch secrets from Keep Your Secrets ───────────────────
def fetch_from_kys(key_name):
    """Fetch a secret value from Keep Your Secrets (KYS) API."""
    kys_token = os.environ.get('KYS_API_TOKEN', '')
    kys_url   = os.environ.get('KYS_URL', 'https://ai-api-tracker-production.up.railway.app')
    if not kys_token:
        return None
    try:
        payload = json.dumps({'key': key_name}).encode()
        req = urllib.request.Request(
            f'{kys_url}/api/fetch-key',
            data=payload,
            headers={'Authorization': f'Bearer {kys_token}',
                     'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            if data.get('ok'):
                # single key
                return data.get('value') or data.get('secret') or None
    except Exception:
        pass
    return None

def get_env_or_kys(env_var, kys_key):
    """Return env var if set, otherwise fetch from KYS."""
    val = os.environ.get(env_var, '')
    if val:
        return val
    return fetch_from_kys(kys_key) or ''

# Load Stripe secrets — env var first, fall back to KYS
stripe.api_key   = get_env_or_kys('STRIPE_SECRET_KEY', 'stripe_secret')
STRIPE_PK        = get_env_or_kys('STRIPE_PUBLISHABLE_KEY', 'stripe_publishable')
STRIPE_WH_SECRET = get_env_or_kys('STRIPE_WEBHOOK_SECRET', 'stripe_webhook')

# Price IDs — set these as Railway env vars after creating products in Stripe
STRIPE_PRICE_PRO      = os.environ.get('STRIPE_PRICE_PRO', '')       # $19/mo
STRIPE_PRICE_BUSINESS = os.environ.get('STRIPE_PRICE_BUSINESS', '')  # $49/mo

app = Flask(__name__)

def _get_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    data_dir = os.environ.get('RAILWAY_DATA_DIR') or os.environ.get('DATA_DIR') or '/data'
    key_file = os.path.join(data_dir, 'secret_key')
    try:
        os.makedirs(data_dir, exist_ok=True)
        if os.path.exists(key_file):
            with open(key_file) as f:
                key = f.read().strip()
            if key:
                return key
        import secrets as _sec
        key = _sec.token_hex(32)
        with open(key_file, 'w') as f:
            f.write(key)
        return key
    except Exception:
        import secrets as _sec
        return _sec.token_hex(32)

app.secret_key = _get_secret_key()

import secrets as _secrets_csrf

def _get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = _secrets_csrf.token_hex(32)
    return session['csrf_token']

def _validate_csrf():
    if request.method != 'POST':
        return True
    if request.path.startswith('/api/'):
        return True
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
    return token == session.get('csrf_token', '')

app.jinja_env.globals['csrf_token'] = _get_csrf_token


@app.before_request
def _csrf_protect():
    """Enforce CSRF on all state-changing requests."""
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if request.path.startswith('/api/'):
            return  # API routes use token auth, skip CSRF
        if not _validate_csrf():
            from flask import abort
            abort(403)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
            identity_md   TEXT DEFAULT '',
            soul_md       TEXT DEFAULT '',
            memory_md     TEXT DEFAULT '',
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
        CREATE TABLE IF NOT EXISTS agent_actions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            method      TEXT NOT NULL DEFAULT 'POST',
            url         TEXT NOT NULL,
            headers_json TEXT DEFAULT '{}',
            body_template TEXT DEFAULT '{}',
            enabled     INTEGER DEFAULT 1,
            created     TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_actions_agent ON agent_actions(agent_id);
        CREATE TABLE IF NOT EXISTS tickets (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id            INTEGER NOT NULL,
            priority           TEXT NOT NULL DEFAULT 'normal',
            subject            TEXT NOT NULL,
            description        TEXT NOT NULL,
            status             TEXT NOT NULL DEFAULT 'open',
            admin_reply        TEXT DEFAULT '',
            replied_at         TEXT DEFAULT NULL,
            hosting_login_url  TEXT DEFAULT '',
            hosting_provider   TEXT DEFAULT '',
            website_url        TEXT DEFAULT '',
            install_notes      TEXT DEFAULT '',
            created            TEXT DEFAULT (datetime('now')),
            updated            TEXT DEFAULT (datetime('now')),
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

def migrate_chat_reports():
    """Add chat_reports table for AI-generated conversation intelligence."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute('''
            CREATE TABLE IF NOT EXISTS chat_reports (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   TEXT NOT NULL,
                report_type TEXT NOT NULL,
                content    TEXT NOT NULL,
                msg_count  INTEGER DEFAULT 0,
                created    TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(agent_id) REFERENCES agents(id)
            )
        ''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_reports_agent ON chat_reports(agent_id)')
        db.commit()
    except Exception:
        pass
    finally:
        db.close()


def migrate_learned_facts():
    """Add learned_facts table for auto-extracted memory."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute('''
            CREATE TABLE IF NOT EXISTS learned_facts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   TEXT NOT NULL,
                session_id TEXT,
                fact       TEXT NOT NULL,
                approved   INTEGER DEFAULT 0,
                created    TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(agent_id) REFERENCES agents(id)
            )
        ''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_facts_agent ON learned_facts(agent_id)')
        db.commit()
    except Exception:
        pass
    finally:
        db.close()


def migrate_brain_columns():
    """Add identity_md, soul_md, memory_md columns + ensure agent_actions table."""
    try:
        db = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in db.execute("PRAGMA table_info(agents)").fetchall()]
        for col in ['identity_md', 'soul_md', 'memory_md']:
            if col not in cols:
                db.execute(f"ALTER TABLE agents ADD COLUMN {col} TEXT DEFAULT ''")
                app.logger.info(f'Added column: {col}')
        # Ensure agent_actions table exists (for upgrades from older DB)
        db.execute('''
            CREATE TABLE IF NOT EXISTS agent_actions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id     TEXT NOT NULL,
                name         TEXT NOT NULL,
                description  TEXT NOT NULL DEFAULT '',
                method       TEXT NOT NULL DEFAULT 'POST',
                url          TEXT NOT NULL,
                headers_json TEXT DEFAULT '{}',
                body_template TEXT DEFAULT '{}',
                enabled      INTEGER DEFAULT 1,
                created      TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
            )''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_actions_agent ON agent_actions(agent_id)')
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f'Brain/actions migration error: {e}')

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
migrate_brain_columns()
migrate_learned_facts()
migrate_chat_reports()


def extract_and_store_facts(agent_id, session_id, conversation_snippet, model, api_key):
    """Ask the LLM to extract learnable facts from a conversation and store them."""
    try:
        prompt = [
            {'role': 'system', 'content': (
                'You are a memory extraction assistant. '
                'Read this conversation snippet and extract any NEW facts worth remembering long-term. '
                'Examples: user name, preferences, business details, repeated questions, complaints, use cases. '
                'Output ONLY a JSON array of short fact strings, max 5 facts. '
                'If nothing new is worth remembering, output an empty array []. '
                'Example output: ["User\'s name is Sarah", "Interested in the Pro plan", "Uses the widget for e-commerce"]'
            )},
            {'role': 'user', 'content': f'Conversation:\n{conversation_snippet[:2000]}'}
        ]
        result = call_openrouter(prompt, model, api_key)
        result = result.strip()
        if result.startswith('```'):
            result = result.split('\n', 1)[-1].rsplit('```', 1)[0].strip()
        import json as _json
        facts = _json.loads(result)
        if not isinstance(facts, list): return
        db = get_db()
        for fact in facts[:5]:
            fact = str(fact).strip()
            if len(fact) > 10:
                db.execute(
                    'INSERT INTO learned_facts(agent_id, session_id, fact) VALUES(?,?,?)',
                    (agent_id, session_id, fact)
                )
        db.commit()
        db.close()
    except Exception:
        pass  # Never crash the main chat flow


# ── OpenRouter chat ───────────────────────────────────────────────────────────

import requests as _req

def call_openrouter(messages, model, api_key):
    # If no key provided, fall back to KYS
    if not api_key:
        api_key = fetch_from_kys('openrouter') or ''
    try:
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {api_key}',
                     'Content-Type': 'application/json',
                     'HTTP-Referer': 'https://ai-agent-widget-production.up.railway.app',
                     'X-Title': 'Alexander AI Agent'},
            json={'model': model, 'messages': messages, 'max_tokens': 1500},
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


# ── Action Execution Engine ───────────────────────────────────────────────────

def build_actions_prompt(actions, agent_id, agent_api_key, base_url):
    """Build tool-use instructions injected into the system prompt."""
    lines = [
        "\n\n---\n## ACTIONS YOU CAN PERFORM\n",
        "When the user asks you to DO something inside the app, execute an action.",
        "To execute an action, include EXACTLY this JSON block on its own line in your reply:",
        '\n```action\n{"action": "ACTION_NAME", "params": {"key": "value"}}\n```\n',
    ]
    if actions:
        lines.append("Available actions:")
        for a in actions:
            lines.append(f"- **{a['name']}**: {a['description']}")
    else:
        lines.append("You have no actions defined yet — but you can create them yourself (see below).")
    lines.append("\nAfter the action block, continue your reply explaining what you did.")
    lines.append("Only execute an action when the user explicitly asks you to DO something.")
    lines.append("""
## CRITICAL ACTION RULES — ALWAYS FOLLOW THESE:
1. LOOKUP BEFORE ACTING: When the user gives you a NAME (e.g. 'John Smith') instead of a numeric ID, ALWAYS call lookup_claim/lookup first to find the correct numeric ID. NEVER guess or assume an ID.
2. VERIFY AFTER DELETING: After any delete action, immediately call list_claims (or the equivalent list action) and show the user the updated list to CONFIRM the item is actually gone.
3. VERIFY AFTER UPDATING: After any update (status change, add room, etc.), call get_claim or get_dashboard to confirm the change was applied.
4. NEVER REPORT SUCCESS WITHOUT CONFIRMING: Do not tell the user something is done unless you have verified it via a follow-up API call. The API response alone is not enough — always check.
5. SHOW YOUR WORK: Tell the user exactly what ID you found, what you deleted/changed, and show the verification result.
6. MULTIPLE ACTIONS: If the user asks for several things at once (e.g. "add 5 team members" or "create these 3 claims"), output ONE ```action``` block per item in your reply. The engine executes ALL blocks automatically. Never stop at just the first one.""")
    # Self-management API
    lines.append(f"""
## SELF-MANAGEMENT: You can add your OWN actions
If you need a capability you don't have yet, call this API to add it:

POST {base_url}/agent/{agent_id}/actions/api
Authorization: Bearer {agent_api_key}
Content-Type: application/json

Body:
{{"name":"action_name","description":"when to use it","method":"POST","url":"https://target-app.com/endpoint","body":{{"param":"{{param}}"}}}}

You can also:
- GET {base_url}/agent/{agent_id}/actions/api  — list your current actions
- DELETE {base_url}/agent/{agent_id}/actions/api  — body: {{"name":"action_name"}}

When a user asks you to do something you can't do yet, tell them you're adding the capability and call the API.
""")
    lines.append("---")
    return "\n".join(lines)

def execute_action(action, params, agent_api_key):
    """Execute a single action — HTTP call to the target app."""
    url = action["url"]
    for k, v in params.items():
        url = url.replace("{" + k + "}", str(v))

    try:
        headers = json.loads(action["headers_json"] or "{}")
    except Exception:
        headers = {}
    if "Authorization" not in headers and agent_api_key:
        headers["Authorization"] = f"Bearer {agent_api_key}"
    headers["Content-Type"] = "application/json"

    try:
        body_str = action["body_template"] or "{}"
        for k, v in params.items():
            body_str = body_str.replace("{" + k + "}", str(v))
        body = json.loads(body_str)
        body.update({k: v for k, v in params.items() if k not in body})
    except Exception:
        body = dict(params)

    try:
        method = (action["method"] or "POST").upper()
        if method == "GET":
            r = _req.get(url, headers=headers, params=params, timeout=15)
        elif method == "DELETE":
            r = _req.delete(url, headers=headers, timeout=15)
        else:
            r = _req.post(url, headers=headers, json=body, timeout=15)
        try:
            result = r.json()
        except Exception:
            result = {"text": r.text[:500]}
        return {"ok": r.ok, "status": r.status_code, "result": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def parse_action_call(reply_text):
    """Extract FIRST action JSON block from AI reply (legacy single-action support)."""
    import re
    match = re.search(r'```action\s*\n({.*?})\s*\n```', reply_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    return None


def parse_all_action_calls(reply_text):
    """Extract ALL action JSON blocks from AI reply — supports multiple actions per message."""
    import re
    actions = []
    for match in re.finditer(r'```action[\s\S]*?({[\s\S]*?})\s*```', reply_text, re.DOTALL):
        try:
            obj = json.loads(match.group(1))
            # Normalise: accept 'name' or 'action' as the action key
            if 'name' in obj and 'action' not in obj:
                obj['action'] = obj.pop('name')
            actions.append(obj)
        except Exception:
            pass
    return actions


def strip_action_block(reply_text):
    """Remove ALL ```action ... ``` blocks from visible reply."""
    import re
    return re.sub(r'```action[\s\S]*?```\n?', '', reply_text, flags=re.DOTALL).strip()

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


@app.route('/api/analyze-photo-public', methods=['POST', 'OPTIONS'])
def analyze_photo_public():
    """Public endpoint — widget calls this to AI-analyze a photo before sending."""
    if request.method == 'OPTIONS':
        return '', 204
    data     = request.get_json(silent=True) or {}
    img_b64  = data.get('image', '')
    mime     = data.get('mime', 'image/jpeg')
    agent_id = data.get('agent_id', '')
    if not img_b64 or not agent_id:
        return jsonify({'description': ''})
    db    = get_db()
    agent = db.execute('SELECT api_key, model FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent or not agent['api_key']:
        return jsonify({'description': ''})
    try:
        model = normalize_model(agent['model'] or 'openai/gpt-4o-mini')
        reply = call_openrouter([{
            'role': 'user',
            'content': [
                {'type': 'text', 'text': (
                    'You are a professional flood damage adjuster. In 1-2 sentences, '
                    'describe the damage visible in this photo: what is damaged, severity, '
                    'and key repair needs. Be concise and professional.'
                )},
                {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{img_b64}'}}
            ]
        }], model, agent['api_key'])
        return jsonify({'description': reply if not reply.startswith('⚠️') else ''})
    except Exception:
        return jsonify({'description': ''})

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

    # ── Build system prompt: brain files + knowledge base ──
    system_content = agent['system_prompt']

    # Inject IDENTITY.md, SOUL.md, MEMORY.md if set
    brain_sections = []
    if agent['identity_md'] and agent['identity_md'].strip():
        brain_sections.append(f'# IDENTITY\n{agent["identity_md"].strip()}')
    if agent['soul_md'] and agent['soul_md'].strip():
        brain_sections.append(f'# SOUL / PERSONALITY\n{agent["soul_md"].strip()}')
    if agent['memory_md'] and agent['memory_md'].strip():
        brain_sections.append(f'# MEMORY / KNOWLEDGE\n{agent["memory_md"].strip()}')
    if brain_sections:
        system_content = '\n\n'.join(brain_sections) + '\n\n---\n\n' + system_content

    # Inject Knowledge Base
    kb_entries = db.execute(
        'SELECT title, content FROM knowledge_base WHERE agent_id=? ORDER BY created ASC',
        (agent_id,)
    ).fetchall()
    if kb_entries:
        kb_text = '\n\n'.join(
            f"[{e['title'] or 'Knowledge'}]\n{e['content']}" for e in kb_entries
        )
        system_content = system_content + f'\n\n---\nKNOWLEDGE BASE:\n{kb_text[:6000]}\n---'

    # ── Inject visitor memory ──
    if session_id and session_id != 'dashboard-test':
        mem = db.execute(
            'SELECT summary, message_count FROM session_memory WHERE agent_id=? AND session_id=?',
            (agent_id, session_id)
        ).fetchone()
        if mem and mem['summary']:
            system_content += f'\n\n---\nVISITOR MEMORY (returning user):\n{mem["summary"]}\n---'

    # ── Inject available actions ──
    actions = db.execute(
        'SELECT * FROM agent_actions WHERE agent_id=? AND enabled=1 ORDER BY id',
        (agent_id,)
    ).fetchall()
    actions_list = [dict(a) for a in actions]
    base_url = request.host_url.rstrip('/')
    system_content += build_actions_prompt(actions_list, agent_id, agent['api_key'], base_url)

    messages = [{'role': 'system', 'content': system_content}]
    for h in history[-10:]:
        if h.get('role') in ('user', 'assistant') and h.get('content'):
            messages.append({'role': h['role'], 'content': h['content'][:1000]})
    messages.append({'role': 'user', 'content': user_msg})

    reply = call_openrouter(messages, model, agent['api_key'])

    # ── Execute ALL actions Willie called (supports multiple per message) ──
    action_result_text = ''
    action_was_executed = False
    action_name = ''
    action_calls = parse_all_action_calls(reply)
    if action_calls and actions_list:
        results = []
        for ac in action_calls:
            action_name = ac.get('action', '')
            params = ac.get('params', {})
            matched = next((a for a in actions_list if a['name'] == action_name), None)
            if matched:
                exec_result = execute_action(matched, params, agent['api_key'])
                if exec_result.get('ok'):
                    # Include full JSON result so agent can read IDs, values etc.
                    raw_result = exec_result.get('result', {})
                    msg = exec_result.get('message', 'Done')
                    result_json = json.dumps(raw_result, ensure_ascii=False)[:800]
                    results.append(f'✅ **{action_name}**: {msg}\nResult: {result_json}')
                else:
                    err = exec_result.get('error', exec_result.get('result', 'Unknown error'))
                    results.append(f'⚠️ **{action_name}** failed: {err}')
            else:
                results.append(f'❓ Unknown action: {action_name}')
        action_result_text = '\n\n' + '\n'.join(results)
        reply = strip_action_block(reply) + action_result_text
        action_was_executed = True

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

    # ── Extract learnable facts every 6 messages ──
    if session_id and session_id != 'dashboard-test' and len(session_id) > 4:
        total_msgs = db.execute(
            'SELECT COUNT(*) as c FROM messages WHERE agent_id=? AND session_id=?',
            (agent_id, session_id)
        ).fetchone()['c']
        if total_msgs % 6 == 0:
            recent = db.execute(
                'SELECT role, content FROM messages WHERE agent_id=? AND session_id=? ORDER BY ts DESC LIMIT 12',
                (agent_id, session_id)
            ).fetchall()
            if recent:
                snippet = '\n'.join(f"{m['role'].upper()}: {m['content'][:300]}" for m in reversed(recent))
                threading.Thread(
                    target=extract_and_store_facts,
                    args=(agent_id, session_id, snippet, model, agent['api_key']),
                    daemon=True
                ).start()

    db.commit()

    response_data = {'reply': reply}
    try:
        if action_was_executed:
            response_data['action_executed'] = True
            response_data['action_name'] = action_name if 'action_name' in dir() else ''
    except Exception:
        pass
    return jsonify(response_data)

# ── Agent preview (live demo) ─────────────────────────────────────────────────

@app.route('/preview/<agent_id>')
def preview(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('index'))
    return render_template('preview.html', agent=dict(agent))


# ── Agent Brain (IDENTITY.md / SOUL.md / MEMORY.md) ───────────────────────────────


# -- Brain Sync Helper ---------------------------------------------------------

def _push_brain_to_ecdash(identity_md, soul_md, memory_md):
    """Push brain files to EcDash after a save. Silent on failure."""
    try:
        import json as _json
        ecdash_url  = os.environ.get('ECDASH_URL', 'https://jay-portfolio-production.up.railway.app')
        sync_token  = os.environ.get('BRAIN_SYNC_TOKEN', '')
        if not ecdash_url or not sync_token:
            return  # not configured -- skip silently
        payload = _json.dumps({
            'IDENTITY.md': identity_md,
            'SOUL.md':     soul_md,
            'MEMORY.md':   memory_md,
        }).encode('utf-8')
        req = urllib.request.Request(
            ecdash_url.rstrip('/') + '/api/brain/sync',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'X-Brain-Sync-Token': sync_token,
            },
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5): pass
    except Exception:
        pass  # Never block the user -- sync is best-effort

@app.route('/agent/<agent_id>/brain', methods=['GET', 'POST'])
@login_required
def agent_brain(agent_id):
    db  = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        identity_md = request.form.get('identity_md', '').strip()
        soul_md     = request.form.get('soul_md', '').strip()
        memory_md   = request.form.get('memory_md', '').strip()
        db.execute('UPDATE agents SET identity_md=?, soul_md=?, memory_md=? WHERE id=? AND user_id=?',
                   (identity_md, soul_md, memory_md, agent_id, session['user_id']))
        db.commit()
        # — Push to EcDash brain sync if configured —
        _push_brain_to_ecdash(identity_md, soul_md, memory_md)
        flash('Brain files saved! ✅ The agent will use these on the next conversation.', 'success')
        return redirect(url_for('agent_brain', agent_id=agent_id))
    return render_template('agent_brain.html', agent=agent)

@app.route('/agent/<agent_id>/brain/api', methods=['GET'])
@login_required  
def agent_brain_api(agent_id):
    """Return brain files as JSON — for external apps to fetch."""
    db = get_db()
    agent = db.execute('SELECT identity_md, soul_md, memory_md FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'identity_md': agent['identity_md'],
                    'soul_md':     agent['soul_md'],
                    'memory_md':   agent['memory_md']})

@app.route('/agent/<agent_id>/brain/public', methods=['GET'])
def agent_brain_public(agent_id):
    """Token-protected brain export — for EcDash brain sync."""
    sync_token = os.environ.get('BRAIN_SYNC_TOKEN', '')
    if not sync_token:
        return jsonify({'error': 'sync not configured'}), 503
    auth = request.headers.get('X-Brain-Sync-Token', '')
    if not auth or auth != sync_token:
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    agent = db.execute('SELECT identity_md, soul_md, memory_md FROM agents WHERE id=?',
                       (agent_id,)).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'identity_md': agent['identity_md'] or '',
                    'soul_md':     agent['soul_md'] or '',
                    'memory_md':   agent['memory_md'] or ''})

@app.route('/agent/<agent_id>/facts', methods=['GET'])
@login_required
def agent_facts_list(agent_id):
    """List auto-learned facts for an agent."""
    db = get_db()
    agent = db.execute('SELECT id FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    facts = db.execute(
        'SELECT id, fact, approved, session_id, created FROM learned_facts WHERE agent_id=? ORDER BY created DESC LIMIT 100',
        (agent_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(f) for f in facts])


@app.route('/agent/<agent_id>/facts/<int:fact_id>/approve', methods=['POST'])
@login_required
def agent_fact_approve(agent_id, fact_id):
    """Approve a learned fact — appends it to MEMORY.md."""
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    fact = db.execute('SELECT * FROM learned_facts WHERE id=? AND agent_id=?', (fact_id, agent_id)).fetchone()
    if not fact:
        return jsonify({'error': 'not found'}), 404
    # Append to memory_md
    existing = agent['memory_md'] or ''
    from datetime import datetime as _dt
    date_str = _dt.utcnow().strftime('%Y-%m-%d')
    new_memory = existing.rstrip() + f'\n- [{date_str}] {fact["fact"]}'
    db.execute('UPDATE agents SET memory_md=? WHERE id=?', (new_memory.strip(), agent_id))
    db.execute('UPDATE learned_facts SET approved=1 WHERE id=?', (fact_id,))
    db.commit()
    db.close()
    return jsonify({'ok': True, 'memory_md': new_memory.strip()})


@app.route('/agent/<agent_id>/facts/<int:fact_id>', methods=['DELETE'])
@login_required
def agent_fact_delete(agent_id, fact_id):
    """Delete a learned fact."""
    db = get_db()
    agent = db.execute('SELECT id FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    db.execute('DELETE FROM learned_facts WHERE id=? AND agent_id=?', (fact_id, agent_id))
    db.commit()
    db.close()
    return jsonify({'ok': True})


@app.route('/agent/<agent_id>/facts/approve-all', methods=['POST'])
@login_required
def agent_facts_approve_all(agent_id):
    """Approve all pending facts — bulk append to MEMORY.md."""
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    pending = db.execute(
        'SELECT id, fact FROM learned_facts WHERE agent_id=? AND approved=0 ORDER BY created ASC',
        (agent_id,)
    ).fetchall()
    if not pending:
        return jsonify({'ok': True, 'added': 0})
    existing = agent['memory_md'] or ''
    from datetime import datetime as _dt
    date_str = _dt.utcnow().strftime('%Y-%m-%d')
    new_lines = '\n'.join(f'- [{date_str}] {f["fact"]}' for f in pending)
    new_memory = existing.rstrip() + '\n' + new_lines
    db.execute('UPDATE agents SET memory_md=? WHERE id=?', (new_memory.strip(), agent_id))
    ids = [f['id'] for f in pending]
    placeholders = ','.join('?' for _ in ids)
    db.execute(f'UPDATE learned_facts SET approved=1 WHERE id IN ({placeholders})', ids)
    db.commit()
    db.close()
    return jsonify({'ok': True, 'added': len(pending), 'memory_md': new_memory.strip()})


@app.route('/agent/<agent_id>/brain/update', methods=['POST'])
def agent_brain_update(agent_id):
    """Public endpoint — lets the hosted app update memory as agent learns."""
    data     = request.get_json(silent=True) or {}
    token    = data.get('token', '')
    db       = get_db()
    agent    = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    # Verify with agent api_key as token (the app must know its own key)
    if token != agent['api_key']:
        return jsonify({'error': 'unauthorized'}), 401
    memory_md = data.get('memory_md')
    if memory_md is not None:
        db.execute('UPDATE agents SET memory_md=? WHERE id=?', (memory_md.strip(), agent_id))
        db.commit()
    return jsonify({'ok': True})


# ── Agent Actions (CRUD) ─────────────────────────────────────────────────────

@app.route('/agent/<agent_id>/actions')
@login_required
def agent_actions_page(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))
    actions = db.execute('SELECT * FROM agent_actions WHERE agent_id=? ORDER BY id',
                         (agent_id,)).fetchall()
    return render_template('agent_actions.html', agent=agent, actions=actions)

@app.route('/agent/<agent_id>/actions/add', methods=['POST'])
@login_required
def agent_action_add(agent_id):
    db = get_db()
    agent = db.execute('SELECT id FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    name         = request.form.get('name', '').strip()
    description  = request.form.get('description', '').strip()
    method       = request.form.get('method', 'POST').strip().upper()
    url_val      = request.form.get('url', '').strip()
    headers_json = request.form.get('headers_json', '{}').strip() or '{}'
    body_tpl     = request.form.get('body_template', '{}').strip() or '{}'
    if not name or not url_val:
        flash('Action name and URL are required.', 'error')
        return redirect(url_for('agent_actions_page', agent_id=agent_id))
    try: json.loads(headers_json)
    except Exception: headers_json = '{}'
    try: json.loads(body_tpl)
    except Exception: body_tpl = '{}'
    db.execute(
        'INSERT INTO agent_actions (agent_id,name,description,method,url,headers_json,body_template) '
        'VALUES (?,?,?,?,?,?,?)',
        (agent_id, name, description, method, url_val, headers_json, body_tpl))
    db.commit()
    flash(f'Action "{name}" added!', 'success')
    return redirect(url_for('agent_actions_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/actions/<int:action_id>/toggle', methods=['POST'])
@login_required
def agent_action_toggle(agent_id, action_id):
    db = get_db()
    a = db.execute('SELECT enabled FROM agent_actions WHERE id=? AND agent_id=?',
                   (action_id, agent_id)).fetchone()
    if a:
        db.execute('UPDATE agent_actions SET enabled=? WHERE id=?',
                   (0 if a['enabled'] else 1, action_id))
        db.commit()
    return redirect(url_for('agent_actions_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/actions/<int:action_id>/delete', methods=['POST'])
@login_required
def agent_action_delete(agent_id, action_id):
    db = get_db()
    db.execute('DELETE FROM agent_actions WHERE id=? AND agent_id=?', (action_id, agent_id))
    db.commit()
    flash('Action deleted.', 'success')
    return redirect(url_for('agent_actions_page', agent_id=agent_id))

@app.route('/agent/<agent_id>/actions/<int:action_id>/test', methods=['POST'])
@login_required
def agent_action_test(agent_id, action_id):
    db    = get_db()
    agent  = db.execute('SELECT api_key FROM agents WHERE id=? AND user_id=?',
                        (agent_id, session['user_id'])).fetchone()
    action = db.execute('SELECT * FROM agent_actions WHERE id=? AND agent_id=?',
                        (action_id, agent_id)).fetchone()
    if not agent or not action:
        return jsonify({'error': 'not found'}), 404
    params = (request.get_json(silent=True) or {}).get('params', {})
    result = execute_action(dict(action), params, agent['api_key'])
    return jsonify(result)


# ── Agent Self-Management API (Willie adds his own actions) ──────────────────

@app.route('/agent/<agent_id>/actions/api', methods=['POST', 'GET', 'DELETE'])
def agent_actions_api(agent_id):
    """Public API — lets the agent manage its own actions using its API key as auth."""
    auth  = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '').strip() if auth.startswith('Bearer ') else ''
    db    = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
    if not agent:
        return jsonify({'ok': False, 'error': 'Agent not found'}), 404
    if token != agent['api_key']:
        return jsonify({'ok': False, 'error': 'Unauthorized — send your API key as Authorization: Bearer <key>'}), 401

    # GET — list all actions
    if request.method == 'GET':
        actions = db.execute(
            'SELECT id, name, description, method, url, enabled FROM agent_actions WHERE agent_id=? ORDER BY id',
            (agent_id,)).fetchall()
        return jsonify({'ok': True, 'actions': [dict(a) for a in actions]})

    # DELETE — remove an action by name or id
    if request.method == 'DELETE':
        data   = request.get_json(silent=True) or {}
        name   = data.get('name', '').strip()
        act_id = data.get('id')
        if act_id:
            db.execute('DELETE FROM agent_actions WHERE id=? AND agent_id=?', (act_id, agent_id))
        elif name:
            db.execute('DELETE FROM agent_actions WHERE name=? AND agent_id=?', (name, agent_id))
        else:
            return jsonify({'ok': False, 'error': 'Provide name or id to delete'}), 400
        db.commit()
        return jsonify({'ok': True, 'message': 'Action deleted'})

    # POST — add or update an action
    data         = request.get_json(silent=True) or {}
    name         = data.get('name', '').strip().replace(' ', '_')
    description  = data.get('description', '').strip()
    method       = data.get('method', 'POST').strip().upper()
    url_val      = data.get('url', '').strip()
    h            = data.get('headers', data.get('headers_json', {}))
    b            = data.get('body',    data.get('body_template', {}))
    headers_json = json.dumps(h) if isinstance(h, dict) else (h or '{}')
    body_tpl     = json.dumps(b) if isinstance(b, dict) else (b or '{}')

    if not name:
        return jsonify({'ok': False, 'error': 'name is required'}), 400
    if not url_val:
        return jsonify({'ok': False, 'error': 'url is required'}), 400
    if not description:
        return jsonify({'ok': False, 'error': 'description is required'}), 400
    if method not in ('GET', 'POST', 'DELETE'):
        return jsonify({'ok': False, 'error': 'method must be GET, POST, or DELETE'}), 400

    try: json.loads(headers_json)
    except Exception: headers_json = '{}'
    try: json.loads(body_tpl)
    except Exception: body_tpl = '{}'

    # Upsert — update if name already exists
    existing = db.execute('SELECT id FROM agent_actions WHERE name=? AND agent_id=?',
                          (name, agent_id)).fetchone()
    if existing:
        db.execute(
            'UPDATE agent_actions SET description=?,method=?,url=?,headers_json=?,body_template=?,enabled=1 '
            'WHERE name=? AND agent_id=?',
            (description, method, url_val, headers_json, body_tpl, name, agent_id))
        db.commit()
        return jsonify({'ok': True, 'message': f'Action "{name}" updated', 'updated': True})

    db.execute(
        'INSERT INTO agent_actions (agent_id,name,description,method,url,headers_json,body_template) '
        'VALUES (?,?,?,?,?,?,?)',
        (agent_id, name, description, method, url_val, headers_json, body_tpl))
    db.commit()
    return jsonify({'ok': True, 'message': f'Action "{name}" created', 'created': True}), 201

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

# ── Chat Intelligence Reports ─────────────────────────────────────────────────────
REPORT_PROMPTS = {
    'topics': {
        'label': 'Topic Report',
        'icon': '📊',
        'prompt': '''You are analyzing chat logs between an AI assistant and real users.
Your job: extract the TOP TOPICS users are asking about.

Output a JSON object with this exact structure:
{
  "summary": "2-sentence plain-English summary of what users want",
  "top_topics": [
    {"topic": "Topic name", "count": 5, "examples": ["example msg 1", "example msg 2"], "insight": "What this tells us"}
  ],
  "trending": "One sentence on what seems to be growing in interest",
  "recommendation": "One actionable recommendation for the app owner"
}

Rank topics by frequency. Include up to 8 topics. Be specific, not generic.'''
    },
    'health': {
        'label': 'Health Report',
        'icon': '🚑',
        'prompt': '''You are analyzing chat logs between an AI assistant and real users.
Your job: find every sign of app health problems — errors, broken features, user frustration, things not working.

Output a JSON object with this exact structure:
{
  "summary": "Overall health assessment in 2 sentences",
  "health_score": 85,
  "issues": [
    {"title": "Issue name", "severity": "critical|high|medium|low", "description": "What happened", "evidence": "Direct quote or paraphrase from chat", "affected_sessions": 3}
  ],
  "positive_signals": ["Things that are working well based on chats"],
  "recommendation": "Most urgent thing to fix"
}

Severity guide: critical=app broken/unusable, high=feature broken, medium=confusing/frustrating, low=minor annoyance.
If no issues found, return empty issues array and health_score: 100.'''
    },
    'gaps': {
        'label': 'Gap Report',
        'icon': '🕳️',
        'prompt': '''You are analyzing chat logs between an AI assistant and real users.
Your job: find every time the AI could NOT help — said it didn\'t know, couldn\'t do something, gave a vague non-answer, or the user seemed unsatisfied with the response.

Output a JSON object with this exact structure:
{
  "summary": "2-sentence summary of the biggest gaps",
  "gaps": [
    {"capability": "What the user wanted", "frequency": 3, "user_quote": "Direct quote showing the ask", "ai_failure": "What the AI said or failed to do", "fix": "How to address this — add to knowledge base, build a feature, or train the agent"}
  ],
  "quick_wins": ["3 things you could add to the Knowledge Base RIGHT NOW to fix common gaps"],
  "feature_requests": ["Recurring asks that would require building new features"]
}

Be brutal. Every missed opportunity is revenue left on the table.'''
    }
}


def generate_report(agent_id, report_type, model, api_key):
    """Run LLM analysis on recent chat logs and return structured report."""
    db = get_db()
    # Get last 200 user messages for analysis
    msgs = db.execute(
        '''SELECT role, content, session_id, ts
           FROM messages WHERE agent_id=? ORDER BY ts DESC LIMIT 200''',
        (agent_id,)
    ).fetchall()
    if not msgs:
        return {'error': 'No chat history to analyze yet.'}

    # Build conversation transcript grouped by session
    sessions = {}
    for m in reversed(msgs):
        sid = m['session_id'] or 'unknown'
        if sid not in sessions:
            sessions[sid] = []
        sessions[sid].append(f"{m['role'].upper()}: {m['content'][:300]}")

    transcript_parts = []
    for i, (sid, exchanges) in enumerate(list(sessions.items())[:30]):
        transcript_parts.append(f"--- Session {i+1} ---")
        transcript_parts.extend(exchanges[:20])

    transcript = '\n'.join(transcript_parts)[:8000]
    prompt_config = REPORT_PROMPTS[report_type]

    messages = [
        {'role': 'system', 'content': prompt_config['prompt']},
        {'role': 'user', 'content': f'Here are the chat logs to analyze:\n\n{transcript}'}
    ]

    raw = call_openrouter(messages, model, api_key)

    # Strip markdown code fences if present
    clean = raw.strip()
    if clean.startswith('```'):
        clean = clean.split('\n', 1)[-1].rsplit('```', 1)[0].strip()

    try:
        result = json.loads(clean)
    except json.JSONDecodeError:
        result = {'raw': raw, 'parse_error': True}

    # Store report
    db.execute(
        'INSERT INTO chat_reports(agent_id, report_type, content, msg_count) VALUES(?,?,?,?)',
        (agent_id, report_type, json.dumps(result), len(msgs))
    )
    db.commit()
    return result


@app.route('/agent/<agent_id>/reports')
@login_required
def agent_reports(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        flash('Agent not found.', 'error')
        return redirect(url_for('dashboard'))
    # Get latest of each report type
    latest = {}
    for rtype in REPORT_PROMPTS:
        row = db.execute(
            'SELECT * FROM chat_reports WHERE agent_id=? AND report_type=? ORDER BY created DESC LIMIT 1',
            (agent_id, rtype)
        ).fetchone()
        if row:
            latest[rtype] = dict(row)
            latest[rtype]['data'] = json.loads(row['content'])
    msg_count = db.execute('SELECT COUNT(*) as c FROM messages WHERE agent_id=?', (agent_id,)).fetchone()['c']
    return render_template('agent_reports.html', agent=agent, latest=latest,
                           report_types=REPORT_PROMPTS, msg_count=msg_count)


@app.route('/api/agent/<agent_id>/reports/generate', methods=['POST'])
@login_required
def api_generate_report(agent_id):
    db = get_db()
    agent = db.execute('SELECT * FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json() or {}
    report_type = data.get('type', 'topics')
    if report_type not in REPORT_PROMPTS:
        return jsonify({'error': f'Unknown report type: {report_type}'}), 400
    model = agent['model'] or 'openai/gpt-4o-mini'
    result = generate_report(agent_id, report_type, model, agent['api_key'])
    return jsonify({'ok': True, 'type': report_type, 'data': result})


@app.route('/api/agent/<agent_id>/reports/history')
@login_required
def api_reports_history(agent_id):
    db = get_db()
    agent = db.execute('SELECT id FROM agents WHERE id=? AND user_id=?',
                       (agent_id, session['user_id'])).fetchone()
    if not agent:
        return jsonify({'error': 'not found'}), 404
    rows = db.execute(
        'SELECT id, report_type, msg_count, created FROM chat_reports WHERE agent_id=? ORDER BY created DESC LIMIT 50',
        (agent_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


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

# ── Echo Brain Agent Auto-Seed ───────────────────────────────────────────

ECHO_SYSTEM_PROMPT = """You are Echo 👾 — Jay's AI business partner and CEO-level assistant.

You work for Jay Alexander (Ronald J. Alexander Jr.) at Alexander AI Integrated Solutions.

You know everything about his business:

== LIVE APPS (all on Railway) ==
1. AI Agent Widget — https://ai-agent-widget-production.up.railway.app ($19-49/mo)
2. Contractor Pro AI — https://contractor-pro-ai-production.up.railway.app ($99/mo)
3. Pet Vet AI — https://pet-vet-ai-production.up.railway.app ($9.99/mo)
4. Jay's Keep Your Secrets — https://ai-api-tracker-production.up.railway.app ($14.99/mo)
5. Liberty Inventory — thrift store mgmt SaaS ($99+$20/mo)
6. Dropship Shipping — dropshipping SaaS ($299)
7. Consignment Solutions — consignment SaaS ($69.95+$20/mo)
8. Grace — elderly care assistant — https://web-production-1015f.up.railway.app
9. Jay Portfolio — https://jay-portfolio-production.up.railway.app

== TECH STACK ==
Python/Flask, SQLite (WAL mode), Railway hosting, GitHub (Liberty-Emporium org), GitLab backup
All apps: bcrypt auth, rate limiting, security headers, health endpoints, Playwright CI/CD
AI powered by OpenRouter API

== OPEN PRIORITIES ==
- Stripe payments across all 7 apps (biggest revenue unlock)
- Domain: alexanderaiis.com
- Trademark: USPTO TEAS Plus Class 42+35 (~$500)
- Grace v2.0: commercial version for families everywhere
- Email drip sequences on all apps

== YOUR ROLE ==
You help Jay with:
- Business strategy and product decisions
- Feature planning and specs
- Debugging and code guidance
- Marketing copy and pricing
- Competitor research
- New app ideas

Be direct. Have opinions. Think like a CEO. Jay is building a real business — help him move fast.
For actual code execution and deployments, Jay uses the KiloClaw interface."""

def seed_echo_agent():
    """Auto-create the Echo Brain agent for Jay's admin account."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        admin = db.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,)).fetchone()
        if not admin:
            db.close()
            return
        existing = db.execute(
            "SELECT id FROM agents WHERE user_id=? AND name='Echo Brain'",
            (admin['id'],)
        ).fetchone()
        if existing:
            db.execute('UPDATE agents SET system_prompt=?, tagline=? WHERE id=?',
                (ECHO_SYSTEM_PROMPT, 'Your AI business partner — always on, always ready', existing['id']))
            db.commit()
            db.close()
            return
        api_key = os.environ.get('OPENROUTER_API_KEY', os.environ.get('ECHO_API_KEY', '')) or fetch_from_kys('openrouter') or ''
        agent_id = secrets.token_urlsafe(16)
        db.execute('''
            INSERT INTO agents
            (id,user_id,name,tagline,color,avatar,system_prompt,model,api_key,allowed_origins)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (agent_id, admin['id'], 'Echo Brain',
              'Your AI business partner — always on, always ready',
              '#7c6ff7', '👾', ECHO_SYSTEM_PROMPT,
              'openai/gpt-4o-mini', api_key, '*'))
        db.commit()
        db.close()
        app.logger.info(f'Echo Brain agent seeded: {agent_id}')
    except Exception as e:
        app.logger.error(f'Echo seed error: {e}')

seed_echo_agent()


CAKELY_SYSTEM_PROMPT = """You are Cakely \U0001f382, the AI assistant built into Sweet Spot Custom Cakes bakery management system.

You help bakery staff with:
- Looking up orders by customer name or order number
- Checking inventory and low stock alerts
- Finding customer info
- Checking today's pickups and pending orders
- Answering questions about recipes and pricing

You have access to live bakery data through your actions. Use them proactively.
When you find data, present it clearly and helpfully.
Be warm, efficient, and bakery-knowledgeable.
Never make up data — always use your actions to get real info."""


def seed_cakely_agent():
    """Auto-create the Cakely agent for Sweet Spot Custom Cakes."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        admin = db.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,)).fetchone()
        if not admin:
            db.close()
            return
        existing = db.execute(
            "SELECT id FROM agents WHERE user_id=? AND name='Cakely'",
            (admin['id'],)
        ).fetchone()
        if existing:
            db.close()
            return
        api_key = os.environ.get('OPENROUTER_API_KEY', os.environ.get('ECHO_API_KEY', '')) or fetch_from_kys('openrouter') or ''
        import secrets as _s
        agent_id = _s.token_urlsafe(16)
        db.execute('''
            INSERT INTO agents
            (id,user_id,name,tagline,color,avatar,system_prompt,model,api_key,allowed_origins)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (agent_id, admin['id'], 'Cakely',
              'Your Sweet Spot AI \u2014 orders, inventory & team',
              '#f472b6', '\U0001f382', CAKELY_SYSTEM_PROMPT,
              'openai/gpt-4o-mini', api_key, '*'))
        db.commit()
        db.close()
        app.logger.info(f'Cakely agent seeded: {agent_id}')
    except Exception as e:
        app.logger.error(f'Cakely seed error: {e}')


seed_cakely_agent()


ALEXANDER_AI_VOICE_SYSTEM_PROMPT = """You are the AI assistant for Alexander AI Voice — an open source, local-first voice cloning desktop app built by Alexander AI Integrated Solutions.

You help visitors with:
- Understanding what Alexander AI Voice does (local TTS, voice cloning, MCP integration, Captures/dictation)
- Downloading and installing the app (Mac, Windows, Linux)
- Setting up voices and TTS engines (Kokoro, Chatterbox, Qwen3, LuxTTS, and more)
- Using the API and MCP server for agent integrations
- Troubleshooting common issues
- Explaining pricing (it's free and open source, MIT license)
- Pointing to documentation at docs.alexanderaivoice.com
- Connecting visitors to Alexander AI Integrated Solutions for custom AI solutions

Key facts:
- 100% local — no cloud, no API keys needed, no per-character fees
- Voice data never leaves the user's device
- 7 TTS engines, Whisper STT, one local LLM (Qwen 3.5)
- MCP server at localhost:17493 for agent integrations
- Open source on GitHub: Liberty-Emporium/alexander-ai-voice
- Built by Alexander AI Integrated Solutions (alexanderaiis.com)
- Contact: jay@alexanderaiis.com

Be friendly, knowledgeable, and concise. If someone wants a custom AI solution for their business, let them know Alexander AI Integrated Solutions can help."""


def seed_alexander_ai_voice_agent():
    """Auto-create the Alexander AI Voice support agent."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        admin = db.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,)).fetchone()
        if not admin:
            db.close()
            return
        existing = db.execute(
            "SELECT id FROM agents WHERE user_id=? AND name='Alexander AI Voice'",
            (admin['id'],)
        ).fetchone()
        if existing:
            db.execute('UPDATE agents SET system_prompt=?, tagline=? WHERE id=?',
                (ALEXANDER_AI_VOICE_SYSTEM_PROMPT,
                 'Ask me anything about Alexander AI Voice!', existing['id']))
            db.commit()
            agent_id = existing['id']
            app.logger.info(f'Alexander AI Voice agent updated: {agent_id}')
            db.close()
            return
        api_key = os.environ.get('OPENROUTER_API_KEY', os.environ.get('ECHO_API_KEY', '')) or fetch_from_kys('openrouter') or ''
        agent_id = 'alexander-ai-voice'
        # Check if this specific ID is taken
        if db.execute('SELECT id FROM agents WHERE id=?', (agent_id,)).fetchone():
            agent_id = 'alexander-ai-voice-' + secrets.token_urlsafe(4)
        db.execute('''
            INSERT INTO agents
            (id,user_id,name,tagline,color,avatar,system_prompt,model,api_key,allowed_origins)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (agent_id, admin['id'], 'Alexander AI Voice',
              'Ask me anything about Alexander AI Voice!',
              '#7c3aed', '🎙️', ALEXANDER_AI_VOICE_SYSTEM_PROMPT,
              'openai/gpt-4o-mini', api_key, '*'))
        db.commit()
        db.close()
        app.logger.info(f'Alexander AI Voice agent seeded: {agent_id}')
    except Exception as e:
        app.logger.error(f'Alexander AI Voice seed error: {e}')

seed_alexander_ai_voice_agent()


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
STRIPE_PRICE_INSTALLATION = os.environ.get('STRIPE_PRICE_INSTALLATION', '')  # $90 one-time
PLAN_PRICES = {'pro': STRIPE_PRICE_PRO, 'business': STRIPE_PRICE_BUSINESS}
PLAN_HIERARCHY = {'free': 0, 'pro': 1, 'business': 2, 'admin': 9}

@app.route('/billing/checkout/<plan>')
def billing_checkout(plan):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # ── One-time installation service ──
    if plan == 'installation':
        if not STRIPE_PRICE_INSTALLATION:
            flash('Installation service not yet configured. Contact us directly at emporiumandthrift@gmail.com.', 'error')
            return redirect(url_for('pricing'))
        agent_id = request.args.get('agent_id', '')
        try:
            checkout = stripe.checkout.Session.create(
                customer_email=session.get('email'),
                payment_method_types=['card'],
                line_items=[{'price': STRIPE_PRICE_INSTALLATION, 'quantity': 1}],
                mode='payment',
                success_url=request.host_url + 'billing/installation-success',
                cancel_url=request.host_url + 'pricing',
                metadata={
                    'user_id': str(session['user_id']),
                    'plan': 'installation',
                    'agent_id': agent_id,
                    'email': session.get('email', ''),
                },
            )
            return redirect(checkout.url)
        except Exception as e:
            app.logger.error(f'Stripe installation checkout error: {e}')
            flash('Payment error. Please try again.', 'error')
            return redirect(url_for('pricing'))

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

@app.route('/billing/installation-success')
@login_required
def billing_installation_success():
    # Find the most recent installation ticket for this user
    db = get_db()
    ticket = db.execute(
        "SELECT id FROM tickets WHERE user_id=? AND subject LIKE 'Installation Service%' ORDER BY created DESC LIMIT 1",
        (session['user_id'],)
    ).fetchone()
    ticket_id = ticket['id'] if ticket else None
    flash('🎉 Payment received! Please fill in your website details below so we can get started.', 'success')
    return render_template('installation_form.html', ticket_id=ticket_id)


@app.route('/billing/installation-details', methods=['POST'])
@login_required
def billing_installation_details():
    ticket_id         = request.form.get('ticket_id')
    website_url       = request.form.get('website_url', '').strip()[:500]
    hosting_login_url = request.form.get('hosting_login_url', '').strip()[:500]
    hosting_provider  = request.form.get('hosting_provider', '').strip()[:100]
    notes             = request.form.get('notes', '').strip()[:1000]

    db = get_db()
    if ticket_id:
        db.execute(
            """UPDATE tickets SET
               website_url=?, hosting_login_url=?, hosting_provider=?, install_notes=?,
               description = description || '\n\n--- INSTALLATION DETAILS ---\nWebsite: ' || ? || '\nHosting Login: ' || ? || '\nProvider: ' || ? || '\nNotes: ' || ?,
               updated=datetime('now')
               WHERE id=? AND user_id=?""",
            (website_url, hosting_login_url, hosting_provider, notes,
             website_url, hosting_login_url, hosting_provider, notes,
             ticket_id, session['user_id'])
        )
    db.commit()
    flash('✅ Details saved! We\'ll have your agent installed within 24 hours.', 'success')
    return redirect(url_for('tickets_page'))


def migrate_ticket_install_columns():
    """Add installation columns to tickets table if they don't exist."""
    try:
        db = sqlite3.connect(DB_PATH)
        for col, defn in [
            ('hosting_login_url', "TEXT DEFAULT ''"),
            ('hosting_provider',  "TEXT DEFAULT ''"),
            ('website_url',       "TEXT DEFAULT ''"),
            ('install_notes',     "TEXT DEFAULT ''"),
        ]:
            try:
                db.execute(f'ALTER TABLE tickets ADD COLUMN {col} {defn}')
            except Exception:
                pass
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f'Ticket migration error: {e}')

migrate_ticket_install_columns()

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
            user_id  = data['metadata'].get('user_id')
            plan     = data['metadata'].get('plan', 'pro')
            cus_id   = data.get('customer')
            sub_id   = data.get('subscription')
            agent_id = data['metadata'].get('agent_id', '')
            email    = data['metadata'].get('email', '')

            if plan == 'installation' and user_id:
                # Auto-create a support ticket for the installation job
                subject = f'Installation Service — {email}'
                desc    = f'Customer purchased Done-For-You Installation ($90).\n\nEmail: {email}\nAgent ID: {agent_id or "not specified"}\n\nAction needed: Install embed code in their .html file and deliver within 24 hours.'
                db.execute(
                    "INSERT INTO tickets(user_id, priority, subject, description, status) VALUES(?,?,?,?,?)",
                    (int(user_id), 'urgent', subject, desc, 'open')
                )
                db.commit()
                app.logger.info(f'Installation ticket created for user {user_id}')
            elif user_id:
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

# ── KYS KEY ROTATION WEBHOOK ─────────────────────────────────────────────
# KYS calls this when it rotates a client key.
# We store a pending notification so the agent delivers it next time
# the customer opens the chat widget.

def _init_rotation_notifications_table():
    try:
        db = sqlite3.connect(DB_PATH)
        db.execute('''
            CREATE TABLE IF NOT EXISTS rotation_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_email TEXT DEFAULT '',
                new_key TEXT NOT NULL,
                kys_url TEXT DEFAULT '',
                next_rotation TEXT DEFAULT '',
                delivered INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f'rotation_notifications init error: {e}')

_init_rotation_notifications_table()

KYS_WEBHOOK_SECRET = os.environ.get('KYS_WEBHOOK_SECRET', '')

@app.route('/api/kys/rotation-webhook', methods=['POST'])
def kys_rotation_webhook():
    """Receives key rotation events from KYS.
    Stores a pending notification to deliver to the customer via the chat widget.
    Optional: set KYS_WEBHOOK_SECRET env var for HMAC verification.
    """
    # Optional signature verification
    if KYS_WEBHOOK_SECRET:
        sig = request.headers.get('X-KYS-Signature', '')
        expected = __import__('hmac').new(
            KYS_WEBHOOK_SECRET.encode(),
            request.get_data(),
            'sha256'
        ).hexdigest()
        if not __import__('hmac').compare_digest(sig, expected):
            return jsonify({'error': 'Invalid signature'}), 403

    data = request.get_json(silent=True) or {}
    event        = data.get('event', '')
    app_name     = (data.get('app_name') or '').strip()
    client_id    = (data.get('client_id') or '').strip()
    client_email = (data.get('client_email') or client_id).strip()
    new_key      = (data.get('new_key') or '').strip()
    next_rotation = (data.get('next_rotation') or '').strip()
    kys_url      = (data.get('kys_url') or 'https://ai-api-tracker-production.up.railway.app').strip()

    if event != 'key_rotated' or not app_name or not client_id or not new_key:
        return jsonify({'ok': False, 'error': 'Missing required fields'}), 400

    db = get_db()
    db.execute('''
        INSERT INTO rotation_notifications
        (app_name, client_id, client_email, new_key, kys_url, next_rotation)
        VALUES (?,?,?,?,?,?)
    ''', (app_name, client_id, client_email, new_key, kys_url, next_rotation))
    db.commit()
    db.close()

    app.logger.info(f'Rotation notification queued for {app_name}/{client_id}')
    return jsonify({'ok': True, 'message': 'Notification queued for delivery'})


@app.route('/api/kys/pending-notification', methods=['GET'])
def kys_pending_notification():
    """Widget JS polls this on chat open to check if there's a key rotation
    notification waiting for this client.
    Query: ?client_id=user@email.com&app_name=widget
    Returns: {"pending": true, "message": "..."} or {"pending": false}
    Falls back to any app_name if no match found for the given app_name.
    """
    client_id = (request.args.get('client_id') or '').strip()
    app_name  = (request.args.get('app_name') or '').strip()

    if not client_id:
        return jsonify({'pending': False})

    db = get_db()
    # Try exact app_name match first, then fall back to any app for this client
    row = None
    if app_name:
        row = db.execute('''
            SELECT id, new_key, kys_url, next_rotation
            FROM rotation_notifications
            WHERE app_name=? AND client_id=? AND delivered=0
            ORDER BY created_at DESC LIMIT 1
        ''', (app_name, client_id)).fetchone()
    if not row:
        row = db.execute('''
            SELECT id, new_key, kys_url, next_rotation
            FROM rotation_notifications
            WHERE client_id=? AND delivered=0
            ORDER BY created_at DESC LIMIT 1
        ''', (client_id,)).fetchone()

    if not row:
        db.close()
        return jsonify({'pending': False})

    # Mark as delivered
    db.execute('UPDATE rotation_notifications SET delivered=1 WHERE id=?', (row['id'],))
    db.commit()
    db.close()

    kys_url = row['kys_url'] or 'https://ai-api-tracker-production.up.railway.app'
    next_rot = row['next_rotation'] or ''
    next_rot_str = f' Your next rotation is scheduled for {next_rot[:10]}.' if next_rot else ''

    message = (
        f"🔄 **Your API key has been rotated!**\n\n"
        f"Your new key is ready and waiting for you.{next_rot_str}\n\n"
        f"🔑 **Pick up your new key here:**\n"
        f"{kys_url}\n\n"
        f"Just log in and your updated key will be right there. "
        f"Your old key will continue working for 24 hours to give you time to update."
    )

    return jsonify({
        'pending': True,
        'message': message,
        'kys_url': kys_url
    })

# ── END KYS ROTATION WEBHOOK ───────────────────────────────────────────


if __name__ == '__main__':
    app.run(debug=False, port=5000)
