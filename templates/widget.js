(function() {
  'use strict';
  if (window.__AlexanderAI_{{ agent.id | replace('-','_') }}) return;
  window.__AlexanderAI_{{ agent.id | replace('-','_') }} = true;

  var AGENT_ID  = '{{ agent.id }}';
  var BASE_URL  = '{{ base_url }}';
  var COLOR     = '{{ color }}';
  var AVATAR    = '{{ avatar }}';
  var NAME      = '{{ name | e }}';
  var TAGLINE   = '{{ tagline | e }}';
  var history   = [];
  var sessionId = 'sess_' + Math.random().toString(36).slice(2);
  var open      = false;

  // ── Inject styles ──
  var style = document.createElement('style');
  style.textContent = `
    #aai-bubble {
      position:fixed; bottom:24px; right:24px; z-index:99999;
      width:56px; height:56px; border-radius:50%;
      background:${COLOR}; color:#fff; font-size:26px;
      display:flex; align-items:center; justify-content:center;
      cursor:pointer; box-shadow:0 4px 20px rgba(0,0,0,0.25);
      border:none; transition:transform 0.2s, box-shadow 0.2s;
      font-family:inherit;
    }
    #aai-bubble:hover { transform:scale(1.08); box-shadow:0 6px 28px rgba(0,0,0,0.3); }
    #aai-window {
      position:fixed; bottom:92px; right:24px; z-index:99998;
      width:360px; height:520px; max-height:calc(100vh - 120px);
      background:#fff; border-radius:16px;
      box-shadow:0 8px 40px rgba(0,0,0,0.18);
      display:none; flex-direction:column; overflow:hidden;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      border:1px solid rgba(0,0,0,0.08);
    }
    #aai-window.open { display:flex; }
    #aai-header {
      background:${COLOR}; color:#fff; padding:14px 16px;
      display:flex; align-items:center; gap:10px; flex-shrink:0;
    }
    #aai-header-avatar { font-size:24px; }
    #aai-header-info { flex:1; }
    #aai-header-name { font-weight:700; font-size:15px; line-height:1.2; }
    #aai-header-tagline { font-size:11px; opacity:0.85; margin-top:1px; }
    #aai-close {
      background:none; border:none; color:#fff; font-size:20px;
      cursor:pointer; padding:0; opacity:0.8; line-height:1;
    }
    #aai-close:hover { opacity:1; }
    #aai-msgs {
      flex:1; overflow-y:auto; padding:16px; display:flex;
      flex-direction:column; gap:10px; background:#f8f9fa;
    }
    .aai-msg {
      max-width:82%; padding:10px 13px; border-radius:14px;
      font-size:14px; line-height:1.5; word-wrap:break-word;
    }
    .aai-msg.user {
      align-self:flex-end; background:${COLOR}; color:#fff;
      border-bottom-right-radius:4px;
    }
    .aai-msg.bot {
      align-self:flex-start; background:#fff; color:#1a1a1a;
      border:1px solid #e5e7eb; border-bottom-left-radius:4px;
      box-shadow:0 1px 3px rgba(0,0,0,0.06);
    }
    .aai-msg.bot.typing { color:#9ca3af; font-style:italic; }
    #aai-footer {
      padding:12px; border-top:1px solid #e5e7eb;
      background:#fff; flex-shrink:0;
    }
    #aai-form { display:flex; gap:8px; }
    #aai-input {
      flex:1; padding:9px 13px; border-radius:22px;
      border:1.5px solid #e5e7eb; font-size:14px; outline:none;
      background:#f9fafb; transition:border 0.2s;
    }
    #aai-input:focus { border-color:${COLOR}; background:#fff; }
    #aai-send {
      width:36px; height:36px; border-radius:50%;
      background:${COLOR}; color:#fff; border:none;
      cursor:pointer; font-size:16px; display:flex;
      align-items:center; justify-content:center;
      flex-shrink:0; transition:opacity 0.2s;
    }
    #aai-send:hover { opacity:0.85; }
    #aai-send:disabled { opacity:0.4; cursor:not-allowed; }
    #aai-branding {
      text-align:center; font-size:10px; color:#9ca3af;
      padding:4px 0 8px; letter-spacing:0.02em;
    }
    #aai-branding a { color:${COLOR}; text-decoration:none; }
    @media(max-width:480px){
      #aai-window { width:calc(100vw - 24px); right:12px; bottom:80px; }
      #aai-bubble { bottom:16px; right:16px; }
    }
  `;
  document.head.appendChild(style);

  // ── Build DOM ──
  var bubble = document.createElement('button');
  bubble.id = 'aai-bubble';
  bubble.setAttribute('aria-label', 'Chat with ' + NAME);
  bubble.textContent = AVATAR;

  var win = document.createElement('div');
  win.id = 'aai-window';
  win.setAttribute('role', 'dialog');
  win.setAttribute('aria-label', NAME + ' chat');
  win.innerHTML = `
    <div id="aai-header">
      <span id="aai-header-avatar">${AVATAR}</span>
      <div id="aai-header-info">
        <div id="aai-header-name">${NAME}</div>
        <div id="aai-header-tagline">${TAGLINE}</div>
      </div>
      <button id="aai-close" aria-label="Close chat">✕</button>
    </div>
    <div id="aai-msgs"></div>
    <div id="aai-footer">
      <form id="aai-form">
        <input id="aai-input" type="text" placeholder="Ask me anything..." autocomplete="off" maxlength="2000">
        <button id="aai-send" type="submit" aria-label="Send">➤</button>
      </form>
      <div id="aai-branding">Powered by <a href="https://alexanderaiis.com" target="_blank">Alexander AI</a></div>
    </div>
  `;

  document.body.appendChild(bubble);
  document.body.appendChild(win);

  // ── Helpers ──
  function addMsg(role, text) {
    var msgs = document.getElementById('aai-msgs');
    var el = document.createElement('div');
    el.className = 'aai-msg ' + role;
    el.textContent = text;
    msgs.appendChild(el);
    msgs.scrollTop = msgs.scrollHeight;
    return el;
  }

  function setTyping(on) {
    var existing = document.getElementById('aai-typing');
    if (on && !existing) {
      var el = addMsg('bot typing', NAME + ' is typing…');
      el.id = 'aai-typing';
    } else if (!on && existing) {
      existing.remove();
    }
  }

  // ── Toggle ──
  function toggleChat() {
    open = !open;
    win.classList.toggle('open', open);
    bubble.textContent = open ? '✕' : AVATAR;
    if (open) {
      document.getElementById('aai-input').focus();
      if (!document.querySelector('.aai-msg')) {
        addMsg('bot', 'Hi! ' + TAGLINE + ' How can I help you today?');
      }
    }
  }

  bubble.addEventListener('click', toggleChat);
  document.getElementById('aai-close').addEventListener('click', toggleChat);

  // ── Send message ──
  document.getElementById('aai-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var input = document.getElementById('aai-input');
    var send  = document.getElementById('aai-send');
    var text  = input.value.trim();
    if (!text) return;

    input.value = '';
    addMsg('user', text);
    history.push({role: 'user', content: text});
    send.disabled = true;
    setTyping(true);

    fetch(BASE_URL + '/chat/' + AGENT_ID, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: text, history: history, session_id: sessionId})
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      setTyping(false);
      var reply = data.reply || data.error || 'Something went wrong.';
      addMsg('bot', reply);
      history.push({role: 'assistant', content: reply});
      if (history.length > 20) history = history.slice(-20);
    })
    .catch(function() {
      setTyping(false);
      addMsg('bot', 'Connection error. Please try again.');
    })
    .finally(function() { send.disabled = false; });
  });
})();
