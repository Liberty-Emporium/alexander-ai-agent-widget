(function() {
  'use strict';
  if (window.__AlexanderAI_{{ agent.id | replace('-','_') }}) return;
  window.__AlexanderAI_{{ agent.id | replace('-','_') }} = true;

  var AGENT_ID  = '{{ agent.id }}';
  var BASE_URL  = '{{ base_url }}'.replace('http://', 'https://');
  var COLOR     = '{{ color }}';
  var AVATAR    = '{{ avatar }}';
  var NAME      = '{{ name | e }}';
  var TAGLINE   = '{{ tagline | e }}';

  // ── Persistent state ──
  var STORAGE_KEY = 'aai_' + AGENT_ID;
  var CONVS_KEY   = 'aai_convs_' + AGENT_ID;
  var saved = {};
  try { saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch(e) {}

  var history      = saved.history   || [];
  var sessionId    = saved.sessionId || ('sess_' + Math.random().toString(36).slice(2));
  var open         = saved.open      || false;
  var historyOpen  = false;
  var currentTitle = saved.currentTitle || 'New Chat';

  // conversations: [{id, title, ts, msgs:[]}]
  var conversations = [];
  try { conversations = JSON.parse(localStorage.getItem(CONVS_KEY) || '[]'); } catch(e) {}
  var currentConvId = saved.currentConvId || null;

  function saveState() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        open: open, sessionId: sessionId,
        history: history.slice(-40),
        currentTitle: currentTitle,
        currentConvId: currentConvId
      }));
    } catch(e) {}
  }

  function saveConversations() {
    try { localStorage.setItem(CONVS_KEY, JSON.stringify(conversations.slice(-50))); } catch(e) {}
  }

  function flushCurrentConv() {
    if (!history.length) return;
    var title = currentTitle !== 'New Chat' ? currentTitle
      : (history[0] ? history[0].content.slice(0,48) + (history[0].content.length>48?'…':'') : 'Chat');
    if (currentConvId) {
      var idx = conversations.findIndex(function(c){return c.id===currentConvId;});
      if (idx > -1) {
        conversations[idx].title = title;
        conversations[idx].msgs  = history.slice(-40);
        conversations[idx].ts    = Date.now();
      } else {
        conversations.unshift({id:currentConvId, title:title, msgs:history.slice(-40), ts:Date.now()});
      }
    } else {
      var newId = 'c_' + Date.now();
      currentConvId = newId;
      conversations.unshift({id:newId, title:title, msgs:history.slice(-40), ts:Date.now()});
    }
    conversations.sort(function(a,b){return b.ts-a.ts;});
    saveConversations();
    saveState();
  }

  // ── Styles ──
  var style = document.createElement('style');
  style.textContent = `
    #aai-bubble {
      position:fixed; bottom:24px; right:24px; z-index:99999;
      width:56px; height:56px; border-radius:50%;
      background:${COLOR}; color:#fff; font-size:26px;
      display:flex; align-items:center; justify-content:center;
      cursor:pointer; box-shadow:0 4px 20px rgba(0,0,0,.25);
      border:none; transition:transform .2s,box-shadow .2s; font-family:inherit;
    }
    #aai-bubble:hover { transform:scale(1.08); box-shadow:0 6px 28px rgba(0,0,0,.3); }

    #aai-window {
      position:fixed; bottom:92px; right:24px; z-index:99998;
      width:360px; height:520px; max-height:calc(100vh - 120px);
      background:#fff; border-radius:16px;
      box-shadow:0 8px 40px rgba(0,0,0,.18);
      display:none; overflow:hidden; position:fixed;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      border:1px solid rgba(0,0,0,.08);
    }
    #aai-window.open { display:flex; }

    /* ── Inner layout: history panel + chat panel side by side ── */
    #aai-inner {
      display:flex; width:100%; height:100%; transition:transform .25s ease;
    }

    /* ── History panel (slides in from left) ── */
    #aai-hist-panel {
      width:220px; min-width:220px; height:100%; background:#f8f9fa;
      border-right:1px solid #e5e7eb; display:flex; flex-direction:column;
      overflow:hidden; transform:translateX(-220px); transition:transform .25s ease;
      position:absolute; left:0; top:0; bottom:0; z-index:2;
    }
    #aai-window.hist-open #aai-hist-panel { transform:translateX(0); }
    #aai-window.hist-open #aai-chat-panel { transform:translateX(220px); }
    #aai-chat-panel { flex:1; display:flex; flex-direction:column; transition:transform .25s ease; width:100%; }

    #aai-hist-header {
      padding:12px 14px; border-bottom:1px solid #e5e7eb;
      display:flex; align-items:center; justify-content:space-between; flex-shrink:0;
    }
    #aai-hist-header span { font-weight:700; font-size:13px; color:#374151; }
    #aai-new-chat {
      padding:3px 9px; background:${COLOR}; color:#fff; border:none;
      border-radius:6px; font-size:11px; font-weight:700; cursor:pointer; font-family:inherit;
    }
    #aai-hist-list {
      flex:1; overflow-y:auto; padding:6px;
    }
    #aai-hist-list::-webkit-scrollbar { width:3px; }
    #aai-hist-list::-webkit-scrollbar-thumb { background:#d1d5db; border-radius:2px; }
    .aai-conv-item {
      padding:8px 10px; border-radius:8px; cursor:pointer;
      margin-bottom:2px; border:1px solid transparent; transition:all .15s;
      position:relative;
    }
    .aai-conv-item:hover { background:#fff; border-color:#e5e7eb; }
    .aai-conv-item.active { background:#fff; border-color:${COLOR}40; }
    .aai-conv-title {
      font-size:12px; font-weight:600; color:#1f2937;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      padding-right:18px;
    }
    .aai-conv-date { font-size:10px; color:#9ca3af; margin-top:2px; }
    .aai-conv-del {
      position:absolute; right:6px; top:50%; transform:translateY(-50%);
      opacity:0; background:none; border:none; color:#ef4444;
      cursor:pointer; font-size:11px; padding:2px 4px; border-radius:3px;
    }
    .aai-conv-item:hover .aai-conv-del { opacity:1; }
    .aai-hist-empty { padding:20px 12px; text-align:center; color:#9ca3af; font-size:12px; line-height:1.6; }

    /* ── Chat panel ── */
    #aai-header {
      background:${COLOR}; color:#fff; padding:12px 14px;
      display:flex; align-items:center; gap:10px; flex-shrink:0;
    }
    #aai-hist-btn, #aai-new-chat-btn {
      background:rgba(255,255,255,.2); border:none; color:#fff;
      width:28px; height:28px; border-radius:7px; cursor:pointer;
      font-size:14px; display:flex; align-items:center; justify-content:center;
      flex-shrink:0; transition:background .15s;
    }
    #aai-hist-btn:hover, #aai-new-chat-btn:hover { background:rgba(255,255,255,.3); }
    #aai-new-chat-btn { font-size:18px; font-weight:300; }
    #aai-header-info { flex:1; min-width:0; }
    #aai-header-name { font-weight:700; font-size:14px; line-height:1.2; }
    #aai-header-tagline { font-size:10px; opacity:.85; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    #aai-close {
      background:none; border:none; color:#fff; font-size:18px;
      cursor:pointer; padding:0; opacity:.8; line-height:1; flex-shrink:0;
    }
    #aai-close:hover { opacity:1; }

    #aai-msgs {
      flex:1; overflow-y:auto; padding:14px; display:flex;
      flex-direction:column; gap:10px; background:#f8f9fa;
    }
    #aai-msgs::-webkit-scrollbar { width:3px; }
    #aai-msgs::-webkit-scrollbar-thumb { background:#d1d5db; border-radius:2px; }
    .aai-msg {
      max-width:84%; padding:9px 13px; border-radius:14px;
      font-size:13.5px; line-height:1.5; word-wrap:break-word; white-space:pre-wrap;
    }
    .aai-msg.user {
      align-self:flex-end; background:${COLOR}; color:#fff; border-bottom-right-radius:4px;
    }
    .aai-msg.bot {
      align-self:flex-start; background:#fff; color:#1a1a1a;
      border:1px solid #e5e7eb; border-bottom-left-radius:4px;
      box-shadow:0 1px 3px rgba(0,0,0,.05);
    }
    .aai-msg.bot.typing { color:#9ca3af; font-style:italic; }

    #aai-footer { padding:10px 12px; border-top:1px solid #e5e7eb; background:#fff; flex-shrink:0; }
    #aai-form { display:flex; gap:7px; }
    #aai-input {
      flex:1; padding:8px 12px; border-radius:20px;
      border:1.5px solid #e5e7eb; font-size:13px; outline:none;
      background:#f9fafb; transition:border .2s; font-family:inherit;
    }
    #aai-input:focus { border-color:${COLOR}; background:#fff; }
    #aai-send {
      width:34px; height:34px; border-radius:50%; background:${COLOR};
      color:#fff; border:none; cursor:pointer; font-size:15px;
      display:flex; align-items:center; justify-content:center;
      flex-shrink:0; transition:opacity .2s;
    }
    #aai-attach {
      width:34px; height:34px; border-radius:50%; background:#f3f4f6;
      color:#6b7280; border:none; cursor:pointer; font-size:17px;
      display:flex; align-items:center; justify-content:center;
      flex-shrink:0; transition:all .2s;
    }
    #aai-attach:hover { background:#e5e7eb; color:#374151; }
    #aai-send:hover { opacity:.85; }
    #aai-send:disabled { opacity:.4; cursor:not-allowed; }
    #aai-photo-preview {
      display:none; flex-wrap:wrap; gap:6px;
      padding:8px 12px; border-bottom:1px solid #e5e7eb; background:#f9fafb;
    }
    #aai-photo-preview.has-photos { display:flex; }
    .aai-prev-wrap { position:relative; border-radius:8px; overflow:hidden; flex-shrink:0; }
    .aai-prev-wrap img { width:56px; height:56px; object-fit:cover; display:block; }
    .aai-prev-rm {
      position:absolute; top:2px; right:2px; width:16px; height:16px;
      background:rgba(0,0,0,.55); border:none; border-radius:50%; color:#fff;
      font-size:9px; cursor:pointer; display:flex; align-items:center; justify-content:center;
    }
    .aai-ai-tag {
      font-size:10px; color:#6b7280; max-width:80px; line-height:1.3;
      text-align:center; word-break:break-word;
    }
    #aai-branding { text-align:center; font-size:10px; color:#9ca3af; padding:3px 0 6px; }
    #aai-branding a { color:${COLOR}; text-decoration:none; }

    @media(max-width:480px){
      #aai-window { width:calc(100vw - 20px); right:10px; bottom:78px; }
      #aai-bubble { bottom:14px; right:14px; }
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
  win.innerHTML = `
    <div id="aai-inner">
      <!-- History panel -->
      <div id="aai-hist-panel">
        <div id="aai-hist-header">
          <span>💬 History</span>
          <button id="aai-new-chat">+ New</button>
        </div>
        <div id="aai-hist-list"></div>
      </div>

      <!-- Chat panel -->
      <div id="aai-chat-panel">
        <div id="aai-header">
          <button id="aai-hist-btn" title="Chat history">☰</button>
          <div id="aai-header-info">
            <div id="aai-header-name">${NAME}</div>
            <div id="aai-header-tagline">${TAGLINE}</div>
          </div>
          <button id="aai-new-chat-btn" title="New conversation">&#43;</button>
          <button id="aai-close" aria-label="Close">✕</button>
        </div>
        <div id="aai-msgs"></div>
        <div id="aai-footer">
          <div id="aai-photo-preview"></div>
          <form id="aai-form">
            <button id="aai-attach" type="button" title="Attach photo">📎</button>
            <input id="aai-file" type="file" accept="image/*" multiple style="display:none">
            <input id="aai-input" type="text" placeholder="Ask me anything..." autocomplete="off" maxlength="2000">
            <button id="aai-send" type="submit">➤</button>
          </form>
          <div id="aai-branding">Powered by <a href="https://alexanderaiis.com" target="_blank">Alexander AI</a></div>
        </div>
      </div>
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
    var ex = document.getElementById('aai-typing');
    if (on && !ex) { var el = addMsg('bot typing', NAME + ' is typing…'); el.id = 'aai-typing'; }
    else if (!on && ex) ex.remove();
  }

  function tsLabel(ts) {
    if (!ts) return '';
    var d = new Date(ts), now = new Date(), diff = (now - d) / 86400000;
    if (diff < 1) return 'Today';
    if (diff < 2) return 'Yesterday';
    return d.toLocaleDateString('en-US', {month:'short', day:'numeric'});
  }

  // ── History panel ──
  function renderHistPanel() {
    var list = document.getElementById('aai-hist-list');
    if (!conversations.length) {
      list.innerHTML = '<div class="aai-hist-empty">No past conversations yet.<br>Start chatting!</div>';
      return;
    }
    list.innerHTML = '';
    conversations.forEach(function(c) {
      var item = document.createElement('div');
      item.className = 'aai-conv-item' + (c.id === currentConvId ? ' active' : '');
      item.innerHTML =
        '<div class="aai-conv-title">' + c.title.replace(/</g,'&lt;') + '</div>' +
        '<div class="aai-conv-date">' + tsLabel(c.ts) + '</div>' +
        '<button class="aai-conv-del" title="Delete">✕</button>';
      item.querySelector('.aai-conv-del').addEventListener('click', function(e) {
        e.stopPropagation();
        conversations = conversations.filter(function(x){return x.id!==c.id;});
        saveConversations();
        if (currentConvId === c.id) startNewChat();
        renderHistPanel();
      });
      item.addEventListener('click', function() { loadConv(c.id); });
      list.appendChild(item);
    });
  }

  function loadConv(id) {
    var conv = conversations.find(function(c){return c.id===id;});
    if (!conv) return;
    // Save current before switching
    flushCurrentConv();
    currentConvId = id;
    history = (conv.msgs || []).slice();
    currentTitle = conv.title;
    sessionId = 'sess_' + id;
    var msgs = document.getElementById('aai-msgs');
    msgs.innerHTML = '';
    history.forEach(function(m) { addMsg(m.role==='user'?'user':'bot', m.content); });
    if (!history.length) addMsg('bot', 'Hi! ' + TAGLINE + ' How can I help you today?');
    msgs.scrollTop = msgs.scrollHeight;
    saveState();
    renderHistPanel();
    closeHistPanel();
  }

  function startNewChat() {
    flushCurrentConv();
    currentConvId = null;
    currentTitle  = 'New Chat';
    history       = [];
    sessionId     = 'sess_' + Math.random().toString(36).slice(2);
    var msgs = document.getElementById('aai-msgs');
    msgs.innerHTML = '';
    addMsg('bot', 'Hi! ' + TAGLINE + ' How can I help you today?');
    saveState();
    renderHistPanel();
    closeHistPanel();
    document.getElementById('aai-input').focus();
  }

  function toggleHistPanel() {
    historyOpen = !historyOpen;
    win.classList.toggle('hist-open', historyOpen);
    if (historyOpen) renderHistPanel();
  }

  function closeHistPanel() {
    historyOpen = false;
    win.classList.remove('hist-open');
  }

  // ── Restore on load ──
  function restoreHistory() {
    var msgs = document.getElementById('aai-msgs');
    if (!history.length) {
      addMsg('bot', 'Hi! ' + TAGLINE + ' How can I help you today?');
    } else {
      history.forEach(function(m) { addMsg(m.role==='user'?'user':'bot', m.content); });
    }
    msgs.scrollTop = msgs.scrollHeight;
  }

  // ── KYS Rotation Notification ──
  // Called once per chat open. If KYS rotated the customer's API key,
  // the agent delivers a friendly message telling them to check KYS.
  var CLIENT_ID_KEY = 'aai_client_id_' + AGENT_ID;

  function checkRotationNotification() {
    var clientId = '';
    try {
      // Check agent-specific key first, fall back to logged-in user email
      clientId = localStorage.getItem(CLIENT_ID_KEY)
             || localStorage.getItem('aai_current_user_email')
             || '';
    } catch(e) {}
    if (!clientId) return; // no client id stored — not a registered customer
    fetch(BASE_URL + '/api/kys/pending-notification?client_id=' + encodeURIComponent(clientId) + '&app_name=' + encodeURIComponent(AGENT_ID))
      .then(function(r){ return r.json(); })
      .then(function(data) {
        if (data.pending && data.message) {
          // Small delay so the welcome message renders first
          setTimeout(function() {
            addMsg('bot', data.message);
            history.push({role:'assistant', content: data.message});
            saveState();
          }, 600);
        }
      })
      .catch(function(){}); // silent fail
  }

  // ── Toggle chat open/close ──
  function toggleChat() {
    open = !open;
    win.classList.toggle('open', open);
    bubble.textContent = open ? '✕' : AVATAR;
    if (open) {
      var msgs = document.getElementById('aai-msgs');
      if (!msgs.querySelector('.aai-msg')) restoreHistory();
      msgs.scrollTop = msgs.scrollHeight;
      document.getElementById('aai-input').focus();
      checkRotationNotification();
    } else {
      closeHistPanel();
      flushCurrentConv();
    }
    saveState();
  }

  bubble.addEventListener('click', toggleChat);
  document.getElementById('aai-close').addEventListener('click', toggleChat);
  document.getElementById('aai-hist-btn').addEventListener('click', toggleHistPanel);
  document.getElementById('aai-new-chat').addEventListener('click', startNewChat);
  document.getElementById('aai-new-chat-btn').addEventListener('click', startNewChat);

  // ── Auto-open ──
  if (open) {
    win.classList.add('open');
    bubble.textContent = '✕';
    restoreHistory();
    setTimeout(function() {
      var msgs = document.getElementById('aai-msgs');
      msgs.scrollTop = msgs.scrollHeight;
    }, 50);
    checkRotationNotification();
  }

  // ── Photo attach ──
  var pendingPhotos = [];

  document.getElementById('aai-attach').addEventListener('click', function() {
    document.getElementById('aai-file').click();
  });

  document.getElementById('aai-file').addEventListener('change', function() {
    Array.from(this.files).forEach(function(file) {
      var reader = new FileReader();
      reader.onload = function(e) {
        var item = {file:file, b64:e.target.result, aiDesc:'analyzing...'};
        pendingPhotos.push(item);
        renderPhotoPreview();
        analyzePhoto(item, pendingPhotos.length - 1);
      };
      reader.readAsDataURL(file);
    });
    this.value = '';
  });

  function renderPhotoPreview() {
    var wrap = document.getElementById('aai-photo-preview');
    if (!pendingPhotos.length) { wrap.classList.remove('has-photos'); wrap.innerHTML=''; return; }
    wrap.classList.add('has-photos');
    wrap.innerHTML = pendingPhotos.map(function(p, i) {
      return '<div style="display:flex;flex-direction:column;align-items:center;gap:3px">'
        + '<div class="aai-prev-wrap">'
        + '<img src="'+p.b64+'"/>'
        + '<button class="aai-prev-rm" onclick="aaiRemovePhoto('+i+')">\u2715</button>'
        + '</div>'
        + '<div class="aai-ai-tag">'+(p.aiDesc==='analyzing...'?'\u23f3...':p.aiDesc?'\ud83e\udd16 '+p.aiDesc.slice(0,40)+'\u2026':'')+'</div>'
        + '</div>';
    }).join('');
  }

  window.aaiRemovePhoto = function(i) {
    pendingPhotos.splice(i, 1);
    renderPhotoPreview();
  };

  function analyzePhoto(item, idx) {
    var b64pure = item.b64.split(',')[1];
    fetch(BASE_URL + '/api/analyze-photo-public', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({image:b64pure, mime:item.file.type, agent_id:AGENT_ID})
    })
    .then(function(r){return r.json();})
    .then(function(data){ item.aiDesc = data.description || ''; renderPhotoPreview(); })
    .catch(function(){ item.aiDesc = ''; renderPhotoPreview(); });
  }

  // ── Send message ──
  document.getElementById('aai-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var input = document.getElementById('aai-input');
    var send  = document.getElementById('aai-send');
    var text  = input.value.trim();
    if (!text && !pendingPhotos.length) return;

    closeHistPanel();

    // Build message content — include AI photo descriptions
    var photoDescs = pendingPhotos.filter(function(p){return p.aiDesc && p.aiDesc!=='analyzing...';}).map(function(p){return p.aiDesc;});
    var msgContent = text;
    if (photoDescs.length) {
      msgContent = (text?text+'\n\n':'') + '['+pendingPhotos.length+' photo(s) attached]\nAI analysis:\n' + photoDescs.join('\n');
    }

    // Show user bubble with thumbnails
    var msgs = document.getElementById('aai-msgs');
    document.getElementById('welcome') && document.getElementById('welcome').remove();
    var userDiv = document.createElement('div');
    userDiv.className = 'aai-msg user';
    var thumbs = pendingPhotos.map(function(p){
      return '<img src="'+p.b64+'" style="width:72px;height:54px;object-fit:cover;border-radius:6px;margin-top:5px;display:block">';
    }).join('');
    userDiv.innerHTML = (text ? text.replace(/</g,'&lt;') : '') + thumbs;
    msgs.appendChild(userDiv);
    msgs.scrollTop = msgs.scrollHeight;

    history.push({role:'user', content: msgContent || '[Photo attached]'});
    if (history.filter(function(m){return m.role==='user';}).length===1) {
      currentTitle = (text || 'Photo').slice(0,48);
    }

    pendingPhotos = [];
    renderPhotoPreview();
    input.value = '';
    saveState();
    send.disabled = true;
    setTyping(true);

    fetch(BASE_URL + '/chat/' + AGENT_ID, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({message: msgContent||'[Photo attached]', history:history.slice(-12), session_id:sessionId})
    })
    .then(function(r){return r.json();})
    .then(function(data) {
      setTyping(false);
      var reply = data.reply || data.error || 'Something went wrong.';
      addMsg('bot', reply);
      history.push({role:'assistant', content:reply});
      if (history.length>40) history=history.slice(-40);
      saveState();
      // Auto-refresh the page after any action so changes are visible immediately
      if (data.action_executed) {
        setTimeout(function() {
          window.location.reload();
        }, 2200);
      }
    })
    .catch(function(){
      setTyping(false);
      addMsg('bot','Connection error. Please try again.');
    })
    .finally(function(){ send.disabled=false; });
  });
})();
