/* 小燕家庭云 · 控制台 SPA（零依赖原生 JS，Python 3.6 后端配套）
   路由：hash（#/overview #/accounts #/gateways #/settings #/logs）
   数据：/admin/api/*（会话 Cookie + X-CSRF-Token） */
(function () {
  'use strict';

  // ==================== 基础工具 ====================
  var CSRF = '';
  var app = document.getElementById('app');
  var currentView = null;

  function h(html) {
    var t = document.createElement('template');
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }
  function ce(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function pad2(n) { return String(n).padStart(2, '0'); }
  function fmtTs(ts) {
    if (!ts) return '—';
    var d = new Date(ts * 1000);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
           ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }
  function fmtDur(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    var d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    if (d) return d + '天' + hh + '小时';
    if (hh) return hh + '小时' + m + '分';
    return m + '分';
  }
  function busy(btn, text) {
    btn.dataset.oldHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>' + esc(text || '处理中…');
  }
  function unbusy(btn) {
    btn.disabled = false;
    if (btn.dataset.oldHtml) btn.innerHTML = btn.dataset.oldHtml;
  }

  // ==================== Toast ====================
  function toast(msg, type) {
    var box = document.getElementById('toasts');
    if (!box) {
      box = ce('div');
      box.id = 'toasts';
      document.body.appendChild(box);
    }
    var t = h('<div class="toast ' + (type === 'err' ? 'err' : 'ok') + '" role="status"></div>');
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(function () {
      t.style.opacity = '0';
      t.style.transition = 'opacity .25s';
      setTimeout(function () { t.remove(); }, 260);
    }, 3800);
  }

  // ==================== 模态框 ====================
  // openModal({title, body|html, input?:{label,value,type,placeholder}, danger?, okText})
  //   → Promise<string|true|null>（取消/Esc → null；有输入框 → 输入值）
  function openModal(o) {
    return new Promise(function (resolve) {
      var ov = document.createElement('div');
      ov.className = 'modal-overlay';
      var inputHtml = o.input
        ? '<label class="f" style="margin-top:12px"><span>' + esc(o.input.label || '') + '</span>' +
          '<input type="' + (o.input.type || 'text') + '" value="' + esc(o.input.value || '') +
          '" placeholder="' + esc(o.input.placeholder || '') + '"></label>'
        : '';
      ov.innerHTML = '<div class="modal" role="dialog" aria-modal="true">' +
        '<h3>' + esc(o.title || '确认') + '</h3>' +
        '<div class="body">' + (o.html || esc(o.body || '')) + '</div>' + inputHtml +
        '<div class="acts">' +
        '<button class="ghost" data-act="cancel">' + esc(o.cancelText || '取消') + '</button>' +
        '<button class="' + (o.danger ? 'danger' : '') + '" data-act="ok">' + esc(o.okText || '确定') + '</button>' +
        '</div></div>';
      document.body.appendChild(ov);
      var inp = ov.querySelector('input');
      if (inp) inp.focus();
      function done(val) {
        document.removeEventListener('keydown', key);
        ov.remove();
        resolve(val);
      }
      function key(e) {
        if (e.key === 'Escape') done(null);
        if (e.key === 'Enter' && inp) { e.preventDefault(); ov.querySelector('[data-act="ok"]').click(); }
      }
      document.addEventListener('keydown', key);
      ov.addEventListener('click', function (e) {
        if (e.target === ov) return done(null);
        var a = e.target.getAttribute && e.target.getAttribute('data-act');
        if (a === 'cancel') done(null);
        if (a === 'ok') done(inp ? inp.value : true);
      });
    });
  }

  // ==================== API ====================
  function api(path, opts) {
    opts = opts || {};
    var headers = { 'Accept': 'application/json' };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.csrf !== false && CSRF) headers['X-CSRF-Token'] = CSRF;
    var p = fetch(path, {
      method: opts.method || 'GET',
      headers: headers,
      credentials: 'same-origin',
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      return r.json().catch(function () { return { ok: false, err: 'HTTP ' + r.status }; });
    }).then(function (d) {
      if (d && d.ok === false && d.err === '未登录') {
        CSRF = '';
        showLogin('会话已过期，请重新登录');
      }
      return d;
    });
    // ★ 2026-10-21 线上验收发现的缺陷：fetch 失败（连接重置/断网）时 promise 断掉，
    //   视图既没有 .catch 也不显示错误，永远停在「加载中…」。这里统一加 15s 超时 +
    //   兜底 catch，把任何失败变成 {ok:false, err}，让各视图能显示错误并允许重试。
    if (!opts.noTimeout) {
      p = Promise.race([p, new Promise(function (_, reject) {
        setTimeout(function () { reject(new Error('请求超时（15s）')); }, 15000);
      })]);
    }
    return p.catch(function (e) {
      return { ok: false, err: '网络错误：' + (e && e.message ? e.message : e) };
    });
  }
  // 统一执行写操作：失败弹 err toast，成功弹 msg toast
  function doAct(btn, action, payload, onDone) {
    if (btn) busy(btn);
    return api('/admin/api/do', { method: 'POST', body: Object.assign({ action: action }, payload || {}) })
      .then(function (d) {
        if (btn) unbusy(btn);
        if (d && d.ok) {
          if (d.msg) toast(d.msg, 'ok');
          if (onDone) onDone(d);
        } else {
          toast((d && d.err) || '操作失败', 'err');
        }
        return d;
      })
      .catch(function (e) {
        if (btn) unbusy(btn);
        toast('网络错误: ' + e, 'err');
        return { ok: false };
      });
  }

  // ==================== 登录视图 ====================
  function showLogin(errMsg) {
    if (currentView && currentView.destroy) { try { currentView.destroy(); } catch (e) {} }
    currentView = null;
    app.innerHTML = '';
    var wrap = h('<div class="login-wrap"></div>');
    wrap.innerHTML = '<div class="login-card">' +
      '<div class="logo"><span class="mark">燕</span>小燕家庭云</div>' +
      '<p class="sub">家庭中心归属与账号管理' +
      (errMsg ? ' · <span style="color:var(--bad)">' + esc(errMsg) + '</span>' : '') + '</p>' +
      '<form id="login-form" novalidate>' +
      '<label class="f"><span>管理员密码</span>' +
      '<input type="password" id="login-pw" placeholder="初始密码见服务器 admin_initial.txt" required></label>' +
      '<button type="submit" id="login-btn" style="width:100%;margin-top:4px;padding:10px">登录</button>' +
      '</form>' +
      '<div style="text-align:center;margin-top:14px;font-size:12.5px;color:var(--muted)">' +
      '新用户在 App 里注册；本页只给管理员用</div></div>';
    app.appendChild(wrap);
    var pw = wrap.querySelector('#login-pw');
    pw.focus();
    wrap.querySelector('#login-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var btn = wrap.querySelector('#login-btn');
      var val = pw.value;
      if (!val) { toast('请输入管理员密码', 'err'); return; }
      busy(btn, '登录中…');
      api('/admin/api/login', { method: 'POST', body: { pw: val } })
        .then(function (d) {
          if (d && d.ok) {
            return api('/admin/api/whoami').then(function (w) {
              CSRF = (w && w.ok && w.csrf) || '';
              if (CSRF) { showApp(); route(); }
              else { unbusy(btn); toast('登录后获取会话失败', 'err'); }
            });
          }
          unbusy(btn);
          toast((d && d.err) || '登录失败', 'err');
        })
        .catch(function () { unbusy(btn); toast('网络错误', 'err'); });
    });
  }

  // ==================== 应用外壳 ====================
  var NAV = [
    ['overview', '概览', '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="1.5" y="1.5" width="13" height="13" rx="2"/><path d="M1.5 6h13M6 6v8.5"/></svg>'],
    ['accounts', '账号', '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="5" r="2.8"/><path d="M2.5 14c1-2.6 3-4 5.5-4s4.5 1.4 5.5 4"/></svg>'],
    ['gateways', '网关', '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="1.5" y="3" width="13" height="10" rx="1.5"/><path d="M4.5 6.5h2M9.5 6.5h2M4.5 9.5h2M9.5 9.5h2"/></svg>'],
    ['settings', '设置', '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4"/></svg>'],
    ['logs', '日志', '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 2.5h7l3 3v8H3z"/><path d="M5.5 7.5h5M5.5 10h3"/></svg>']
  ];

  function showApp() {
    app.innerHTML = '';
    var navHtml = NAV.map(function (n) {
      return '<a href="#/' + n[0] + '" data-nav="' + n[0] + '">' + n[2] + '<span>' + n[1] + '</span></a>';
    }).join('');
    var shell = h(
      '<div class="shell">' +
        '<aside class="sidebar" id="sidebar">' +
          '<div class="brand"><span class="mark">燕</span><div>小燕家庭云<br><small>控制台</small></div></div>' +
          '<nav class="nav">' + navHtml + '</nav>' +
          '<div class="foot">' +
            '<div>已登录 · 会话 8 小时有效</div>' +
            '<div class="row"><span class="mono">api.example.com</span>' +
            '<a href="#" id="logout-link">退出登录</a></div>' +
          '</div>' +
        '</aside>' +
        '<div class="overlay" id="overlay"></div>' +
        '<div class="main">' +
          '<header class="topbar">' +
            '<button class="hamburger" id="hamburger" aria-label="打开菜单">' +
              '<svg width="17" height="17" viewBox="0 0 16 16" stroke="currentColor" stroke-width="1.7"><path d="M2 4h12M2 8h12M2 12h12"/></svg>' +
            '</button>' +
            '<div class="title" id="page-title">小燕家庭云</div>' +
          '</header>' +
          '<div class="content" id="content"></div>' +
        '</div>' +
      '</div>');
    app.appendChild(shell);

    var sidebar = shell.querySelector('#sidebar');
    var overlay = shell.querySelector('#overlay');
    shell.querySelector('#hamburger').addEventListener('click', function () {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('show');
    });
    overlay.addEventListener('click', function () {
      sidebar.classList.remove('open');
      overlay.classList.remove('show');
    });
    shell.querySelector('#logout-link').addEventListener('click', function (e) {
      e.preventDefault();
      api('/admin/api/logout', { method: 'POST', body: {} }).then(function () {
        CSRF = '';
        showLogin();
      });
    });
  }

  // ==================== 路由 ====================
  function route() {
    if (!CSRF) { showLogin(); return; }
    var name = (location.hash.replace(/^#\/?/, '').split('?')[0]) || 'overview';
    if (!VIEWS[name]) name = 'overview';
    if (currentView && currentView.destroy) { try { currentView.destroy(); } catch (e) {} }
    currentView = null;
    var content = document.getElementById('content');
    if (!content) { showApp(); content = document.getElementById('content'); }
    window.scrollTo(0, 0);
    Array.prototype.forEach.call(document.querySelectorAll('.nav a'), function (a) {
      a.classList.toggle('on', a.getAttribute('data-nav') === name);
    });
    var titleMap = { overview: '概览', accounts: '账号', gateways: '网关', settings: '设置', logs: '日志' };
    var t = document.getElementById('page-title');
    if (t) t.textContent = '小燕家庭云 · ' + titleMap[name];
    currentView = VIEWS[name](content);
  }
  window.addEventListener('hashchange', function () { if (CSRF) route(); });

  // ==================== 视图：概览 ====================
  function gwTableHtml(gws) {
    var rows = gws.map(function (g) {
      return '<tr>' +
        '<td data-label="家庭中心"><span class="mono">' + esc(g.uuid) + '</span>' +
          (g.name ? '<br><span class="dim">' + esc(g.name) + '</span>' : '') + '</td>' +
        '<td data-label="状态">' + (g.online
          ? '<span class="dot on"></span>在线'
          : '<span class="dot off"></span>离线') + '</td>' +
        '<td data-label="公网 IP" class="mono dim">' + esc(g.ip || '—') + '</td>' +
        '<td data-label="归属">' + (g.owner
          ? '<span class="mono">' + esc(g.owner) + '</span>'
          : '<span class="dim">未认领</span>') + '</td></tr>';
    }).join('');
    if (!rows) rows = '<tr><td colspan="4"><div class="empty"><div class="big">还没有网关连接过</div>' +
      '接入后会自动出现在这里</div></td></tr>';
    return '<div class="table-wrap"><table class="RespTable"><thead><tr>' +
      '<th>家庭中心</th><th>状态</th><th>公网 IP</th><th>归属</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>';
  }

  function viewOverview(root) {
    root.innerHTML =
      '<div class="page-head"><div><h1>概览</h1><div class="sub" id="ov-sub">加载中…</div></div>' +
      '<div class="acts">' +
        '<label class="switch"><input type="checkbox" id="ov-auto"><span class="track"></span>自动刷新 5s</label>' +
        '<button class="ghost" id="ov-refresh">刷新</button>' +
      '</div></div>' +
      '<div class="grid" id="ov-kpis"></div>' +
      '<div class="card"><h2>网关状态</h2><div id="ov-gws">' +
      '<div class="loading"><span class="spinner"></span>加载中…</div></div></div>' +
      '<div class="card"><h2>运行信息</h2><div class="table-wrap"><table class="RespTable"><tbody>' +
      '<tr><th style="width:170px">API 地址</th><td class="mono">https://api.example.com</td></tr>' +
      '<tr><th>MQTT 长连接</th><td id="ov-sessions">—</td></tr>' +
      '<tr><th>已登记 token</th><td id="ov-tokens">—</td></tr>' +
      '<tr><th>自动认领</th><td id="ov-autoclaim">—</td></tr>' +
      '<tr><th>旧版界面</th><td><a href="/admin?ui=classic">classic 服务端渲染版</a>（排障兜底）</td></tr>' +
      '</tbody></table></div></div>';
    var timer = null;
    function load() {
      api('/admin/api/snapshot').then(function (d) {
        if (!d || !d.ok) {
          document.getElementById('ov-sub').textContent = '加载失败：' + ((d && d.err) || '未知错误');
          return;
        }
        var s = d;
        var gws = s.gateways || [];
        var online = gws.filter(function (g) { return g.online; }).length;
        var owned = gws.filter(function (g) { return g.owner; }).length;
        var unclaimed = gws.length - owned;
        var st = s.stats || {};
        document.getElementById('ov-sub').textContent = '服务已运行 ' + fmtDur(st.uptime);
        document.getElementById('ov-kpis').innerHTML =
          kpi('账号数', Object.keys(s.accounts || {}).length, '') +
          kpi('在线网关', online, '共 ' + gws.length + ' 台') +
          kpi('已归属家庭中心', owned, '未认领 ' + unclaimed + ' 台') +
          kpi('MQTT 长连接', st.sessions || 0, '') +
          kpi('已登记 token', st.tokens || 0, '');
        document.getElementById('ov-gws').innerHTML = gwTableHtml(gws);
        document.getElementById('ov-sessions').textContent = (st.sessions || 0) + ' 条';
        document.getElementById('ov-tokens').textContent = (st.tokens || 0) + ' 个';
        document.getElementById('ov-autoclaim').innerHTML = s.auto_claim
          ? '<span class="tag ok">开启</span>' : '<span class="tag off">关闭</span>';
      });
    }
    function kpi(k, v, extra) {
      return '<div class="kpi"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) +
        (extra ? '<small>' + esc(extra) + '</small>' : '') + '</div></div>';
    }
    root.querySelector('#ov-refresh').addEventListener('click', load);
    root.querySelector('#ov-auto').addEventListener('change', function () {
      if (timer) { clearInterval(timer); timer = null; }
      if (this.checked) {
        timer = setInterval(function () { if (!document.hidden) load(); }, 5000);
      }
    });
    load();
    return {
      reload: load,
      destroy: function () { if (timer) clearInterval(timer); }
    };
  }

  // ==================== 视图：账号 ====================
  function viewAccounts(root) {
    root.innerHTML =
      '<div class="page-head"><div><h1>账号</h1>' +
      '<div class="sub">账号 = 登录 App 用的邮箱；家庭中心决定它能看见哪几台网关</div></div>' +
      '<div class="acts"><input type="text" class="search" id="ac-search" placeholder="搜索账号 / 昵称…"></div></div>' +
      '<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">' +
        '<div class="card"><h2>新建账号</h2>' +
          '<div class="row"><div><label class="f"><span>邮箱（只支持邮箱）</span>' +
            '<input type="email" id="ac-new-uid" placeholder="you@example.com"></label></div>' +
          '<div><label class="f"><span>密码（至少 8 位）</span>' +
            '<input type="text" id="ac-new-pw" placeholder="至少 8 位"></label></div>' +
          '<div class="grow-0"><button id="ac-create">创建</button></div></div>' +
          '<p class="help">也可以让对方在小燕 App 登录页点「注册」自助开通。</p>' +
        '</div>' +
        '<div class="card"><h2>把网关绑定给账号</h2>' +
          '<div class="row"><div><label class="f"><span>账号</span>' +
            '<input type="text" id="ac-bind-uid" placeholder="you@example.com"></label></div>' +
          '<div><label class="f"><span>家庭中心</span><select id="ac-bind-hc"></select></label></div>' +
          '<div class="grow-0"><button id="ac-bind" class="ghost">绑定</button></div></div>' +
        '</div>' +
      '</div>' +
      '<div class="card"><h2>已有账号 <span class="hint" id="ac-count"></span></h2>' +
      '<div id="ac-table"><div class="loading"><span class="spinner"></span>加载中…</div></div></div>';

    var snap = null;
    var query = '';

    function renderTable() {
      var box = document.getElementById('ac-table');
      if (!snap) return;
      var tenants = snap.tenants || {};
      var gws = snap.gateways || [];
      var names = {};
      gws.forEach(function (g) { names[g.uuid] = g.name || ''; });
      var uids = Object.keys(snap.accounts || {}).concat(Object.keys(tenants));
      var seen = {};
      uids = uids.filter(function (u) {
        if (seen[u]) return false;
        seen[u] = true;
        return true;
      }).sort();
      var q = query.trim().toLowerCase();
      if (q) {
        uids = uids.filter(function (u) {
          var a = snap.accounts[u] || {};
          return u.toLowerCase().indexOf(q) >= 0 || (a.nickname || '').toLowerCase().indexOf(q) >= 0;
        });
      }
      document.getElementById('ac-count').textContent = uids.length + ' 个';
      if (!uids.length) {
        box.innerHTML = '<div class="empty"><div class="big">' +
          (q ? '没有匹配的账号' : '还没有账号') + '</div>' +
          (q ? '换个关键字试试' : '用上面的表单创建，或让对方在 App 里注册') + '</div>';
        return;
      }
      var rows = uids.map(function (uid) {
        var a = snap.accounts[uid] || {};
        var hcs = tenants[uid] || [];
        var pwTag = a.enabled === false
          ? '<span class="tag warn">已停用</span>'
          : (a.has_pw ? '<span class="tag ok">已设密码</span>' : '<span class="tag bad">无密码·无法登录</span>');
        var hcHtml = hcs.length
          ? hcs.map(function (hc) {
              return '<span class="hc-chip"><span class="mono">' + esc(hc) + '</span>' +
                (names[hc] ? '<span class="dim">' + esc(names[hc]) + '</span>' : '') +
                '<button data-act="unbind" data-uid="' + esc(uid) + '" data-hc="' + esc(hc) +
                '" title="解绑" aria-label="解绑">×</button></span>';
            }).join('')
          : '<span class="dim">—</span>';
        return '<tr>' +
          '<td data-label="账号" class="mono">' + esc(uid) + '</td>' +
          '<td data-label="密码">' + pwTag + '</td>' +
          '<td data-label="最后登录" class="dim">' + fmtTs(a.last_login) + '</td>' +
          '<td data-label="家庭中心">' + hcHtml + '</td>' +
          '<td data-label="昵称" class="dim">' + esc(a.nickname || '') + '</td>' +
          '<td data-label="操作" class="nowrap">' +
            '<button class="mini ghost" data-act="pw" data-uid="' + esc(uid) + '">改密</button> ' +
            '<button class="mini danger" data-act="del" data-uid="' + esc(uid) + '">删除</button>' +
          '</td></tr>';
      }).join('');
      box.innerHTML = '<div class="table-wrap"><table class="RespTable"><thead><tr>' +
        '<th>账号</th><th>密码状态</th><th>最后登录</th><th>家庭中心</th><th>昵称</th><th>操作</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table></div>';
    }

    function load() {
      api('/admin/api/snapshot').then(function (d) {
        if (!d || !d.ok) return;
        snap = d;
        var sel = document.getElementById('ac-bind-hc');
        var gws = (d.gateways || []).map(function (g) {
          return '<option value="' + esc(g.uuid) + '">' + esc(g.uuid) +
            (g.name ? ' · ' + esc(g.name) : '') + '</option>';
        }).join('');
        sel.innerHTML = gws || '<option value="">（暂无网关）</option>';
        renderTable();
      });
    }

    document.getElementById('ac-search').addEventListener('input', function () {
      query = this.value;
      renderTable();
    });
    document.getElementById('ac-create').addEventListener('click', function () {
      var uid = document.getElementById('ac-new-uid').value.trim();
      var pw = document.getElementById('ac-new-pw').value;
      if (uid.indexOf('@') < 0) { toast('账号必须是邮箱地址', 'err'); return; }
      if (pw.length < 8) { toast('密码至少 8 位', 'err'); return; }
      doAct(this, 'acct_create', { uid: uid, pw: pw }, function () {
        document.getElementById('ac-new-uid').value = '';
        document.getElementById('ac-new-pw').value = '';
        load();
      });
    });
    document.getElementById('ac-bind').addEventListener('click', function () {
      var uid = document.getElementById('ac-bind-uid').value.trim();
      var hc = document.getElementById('ac-bind-hc').value;
      if (!uid || !hc) { toast('账号和家庭中心都要填', 'err'); return; }
      doAct(this, 'acct_bind', { uid: uid, hc: hc }, load);
    });

    document.getElementById('ac-table').addEventListener('click', function (e) {
      var btn = e.target.closest('button[data-act]');
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      var uid = btn.getAttribute('data-uid');
      var hc = btn.getAttribute('data-hc');
      if (act === 'unbind') {
        openModal({
          title: '解绑家庭中心',
          html: '将 <b>' + esc(hc) + '</b> 从账号 <b>' + esc(uid) + '</b> 名下移除？<br>' +
                '<span class="dim">该账号的 App 刷新后将看不到这台网关。</span>',
          danger: true, okText: '解绑'
        }).then(function (ok) {
          if (ok) doAct(null, 'acct_unbind', { uid: uid, hc: hc }, load);
        });
      } else if (act === 'del') {
        openModal({
          title: '删除账号',
          html: '确定删除账号 <b>' + esc(uid) + '</b>？<br>' +
                '<span class="dim">其名下全部家庭中心归属会一并移除，且不可恢复。</span>',
          danger: true, okText: '删除'
        }).then(function (ok) {
          if (ok) doAct(null, 'acct_del', { uid: uid }, load);
        });
      } else if (act === 'pw') {
        openModal({
          title: '修改密码',
          body: '账号：' + uid,
          input: { label: '新密码（至少 8 位）', type: 'password', placeholder: '至少 8 位' },
          okText: '修改'
        }).then(function (val) {
          if (!val) return;
          if (val.length < 8) { toast('密码至少 8 位', 'err'); return; }
          doAct(null, 'acct_pw', { uid: uid, pw: val }, load);
        });
      }
    });

    load();
    return { reload: load, destroy: function () {} };
  }

  // ==================== 视图：网关 ====================
  function viewGateways(root) {
    root.innerHTML =
      '<div class="page-head"><div><h1>网关</h1>' +
      '<div class="sub">「保留」= 不参与自动认领，只能由管理员手工绑定</div></div>' +
      '<div class="acts"><input type="text" class="search" id="gw-search" placeholder="搜索 UUID / 名称 / 归属…"></div></div>' +
      '<div class="card"><div id="gw-table">' +
      '<div class="loading"><span class="spinner"></span>加载中…</div></div></div>' +
      '<div class="card"><h2>认领规则</h2>' +
      '<p class="help" style="margin-top:0">自动认领需要同时满足：网关在线 · 没被任何账号认领 · 不在保留列表 · ' +
      '<b>网关连服务器时的公网 IP 与登录方完全一致</b>。时间窗口当前：<span id="gw-window">—</span>。</p>' +
      '<p class="help">想彻底关掉自动认领，去 <a href="#/settings">设置</a>。</p></div>';

    var snap = null;
    var query = '';

    function renderTable() {
      var box = document.getElementById('gw-table');
      if (!snap) return;
      var reserved = {};
      (snap.reserved || []).forEach(function (u) { reserved[u] = true; });
      var gws = (snap.gateways || []).slice().sort(function (a, b) {
        if (a.online !== b.online) return a.online ? -1 : 1;
        return (a.uuid || '').localeCompare(b.uuid || '');
      });
      var q = query.trim().toLowerCase();
      if (q) {
        gws = gws.filter(function (g) {
          return (g.uuid || '').toLowerCase().indexOf(q) >= 0 ||
                 (g.name || '').toLowerCase().indexOf(q) >= 0 ||
                 (g.owner || '').toLowerCase().indexOf(q) >= 0;
        });
      }
      if (!gws.length) {
        box.innerHTML = '<div class="empty"><div class="big">' +
          (q ? '没有匹配的网关' : '还没有网关连上来') + '</div></div>';
        return;
      }
      var rows = gws.map(function (g) {
        var isRes = !!reserved[g.uuid];
        return '<tr>' +
          '<td data-label="家庭中心"><span class="mono">' + esc(g.uuid) + '</span>' +
            (g.name ? '<br><span class="dim">' + esc(g.name) + '</span>' : '') + '</td>' +
          '<td data-label="状态">' + (g.online
            ? '<span class="tag ok">在线</span>' : '<span class="tag off">离线</span>') + '</td>' +
          '<td data-label="公网 IP" class="mono dim">' + esc(g.ip || '—') + '</td>' +
          '<td data-label="归属">' + (g.owner
            ? '<span class="mono">' + esc(g.owner) + '</span>'
            : '<span class="dim">未认领</span>') + '</td>' +
          '<td data-label="认领">' + (isRes
            ? '<span class="tag warn">已保留</span>' : '<span class="tag off">正常</span>') + '</td>' +
          '<td data-label="操作" class="nowrap">' +
            '<button class="mini ghost" data-act="rename" data-hc="' + esc(g.uuid) +
              '" data-name="' + esc(g.name || '') + '">改名</button> ' +
            '<button class="mini ghost" data-act="' + (isRes ? 'unreserve' : 'reserve') +
              '" data-hc="' + esc(g.uuid) + '">' + (isRes ? '取消保留' : '锁定') + '</button>' +
          '</td></tr>';
      }).join('');
      box.innerHTML = '<div class="table-wrap"><table class="RespTable"><thead><tr>' +
        '<th>家庭中心</th><th>状态</th><th>公网 IP</th><th>归属</th><th>认领</th><th>操作</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table></div>';
    }

    function load() {
      api('/admin/api/snapshot').then(function (d) {
        if (!d || !d.ok) return;
        snap = d;
        var cw = d.claim_window;
        document.getElementById('gw-window').textContent =
          cw === null || cw === undefined ? '不限时间' : (cw <= 0 ? '已禁止' : Math.round(cw / 60) + ' 秒');
        renderTable();
      });
    }

    document.getElementById('gw-search').addEventListener('input', function () {
      query = this.value;
      renderTable();
    });
    document.getElementById('gw-table').addEventListener('click', function (e) {
      var btn = e.target.closest('button[data-act]');
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      var hc = btn.getAttribute('data-hc');
      if (act === 'reserve' || act === 'unreserve') {
        doAct(btn, 'gw_' + act, { hc: hc }, load);
      } else if (act === 'rename') {
        openModal({
          title: '修改网关名称',
          body: hc,
          input: { label: '新名称', value: btn.getAttribute('data-name') || '', placeholder: '家庭中心显示名' },
          okText: '保存'
        }).then(function (val) {
          if (val === null) return;
          if (!val.trim()) { toast('名称不能为空', 'err'); return; }
          doAct(null, 'gw_rename', { hc: hc, name: val.trim() }, load);
        });
      }
    });

    load();
    return { reload: load, destroy: function () {} };
  }

  // ==================== 视图：设置 ====================
  function viewSettings(root) {
    root.innerHTML =
      '<div class="page-head"><div><h1>设置</h1>' +
      '<div class="sub">改完立即生效，并写回 tenants.json / admin.json</div></div></div>' +
      '<div class="card"><h2>自动认领</h2>' +
        '<label class="switch" style="margin-bottom:14px"><input type="checkbox" id="st-auto">' +
          '<span class="track"></span>开启自动认领（同一公网 IP 的注册者自动拿到未认领网关）</label>' +
        '<label class="f"><span>时间窗口（分钟）</span>' +
          '<input type="text" id="st-window" placeholder="留空 = 不限时间"></label>' +
        '<p class="help">留空表示不限制；填 0 = 禁止认领；填正数 = 只在该网关首次上线后的 N 分钟内允许。</p>' +
        '<label class="f"><span>保留列表（每行一个 uuid，不参与自动认领）</span>' +
          '<textarea id="st-reserved" placeholder="box-aa-bb-cc-dd-ee-ff"></textarea></label>' +
        '<button id="st-save">保存</button></div>' +
      '<div class="card"><h2>管理员密码</h2>' +
        '<div class="row"><div><label class="f"><span>当前密码</span>' +
          '<input type="password" id="st-old"></label></div>' +
        '<div><label class="f"><span>新密码（至少 8 位）</span>' +
          '<input type="password" id="st-new"></label></div>' +
        '<div class="grow-0"><button id="st-pw" class="ghost">修改</button></div></div></div>' +
      '<div class="card"><h2>后台来源限制</h2>' +
        '<label class="f"><span>只允许这些 IP 访问 /admin（逗号分隔，留空 = 不限制）</span>' +
          '<input type="text" id="st-ipallow" placeholder="1.2.3.4, 5.6.7.8"></label>' +
        '<p class="help">注意：填了之后如果自己的 IP 变了会进不去，需要 SSH 改 admin.json。</p>' +
        '<button id="st-ip" class="ghost">保存</button></div>';

    function load() {
      api('/admin/api/snapshot').then(function (d) {
        if (!d || !d.ok) return;
        document.getElementById('st-auto').checked = !!d.auto_claim;
        var cw = d.claim_window;
        document.getElementById('st-window').value =
          (cw === null || cw === undefined) ? '' : String(Math.round(cw / 60));
        document.getElementById('st-reserved').value = (d.reserved || []).join('\n');
        document.getElementById('st-ipallow').value = (d.ip_allow || []).join(', ');
      });
    }
    document.getElementById('st-save').addEventListener('click', function () {
      doAct(this, 'set_all', {
        auto_claim: document.getElementById('st-auto').checked,
        claim_window: document.getElementById('st-window').value.trim(),
        reserved: document.getElementById('st-reserved').value
      }, load);
    });
    document.getElementById('st-pw').addEventListener('click', function () {
      var oldPw = document.getElementById('st-old').value;
      var newPw = document.getElementById('st-new').value;
      if (!oldPw) { toast('请填写当前密码', 'err'); return; }
      if (newPw.length < 8) { toast('新密码至少 8 位', 'err'); return; }
      doAct(this, 'admin_pw', { old: oldPw, pw: newPw }, function () {
        document.getElementById('st-old').value = '';
        document.getElementById('st-new').value = '';
      });
    });
    document.getElementById('st-ip').addEventListener('click', function () {
      doAct(this, 'admin_ip', {
        ip_allow: document.getElementById('st-ipallow').value
      }, load);
    });
    load();
    return { reload: load, destroy: function () {} };
  }

  // ==================== 视图：日志 ====================
  function viewLogs(root) {
    root.innerHTML =
      '<div class="page-head"><div><h1>日志</h1>' +
      '<div class="sub" id="lg-sub">cloud4.log 最近 500 行</div></div>' +
      '<div class="acts">' +
        '<label class="switch"><input type="checkbox" id="lg-auto"><span class="track"></span>自动刷新 3s</label>' +
        '<button class="ghost" id="lg-refresh">刷新</button>' +
      '</div></div>' +
      '<div class="logbar"><input type="text" class="search" id="lg-filter" placeholder="过滤关键字…">' +
        '<span class="dim" id="lg-count"></span>' +
        '<button class="ghost mini" id="lg-bottom">跳到最新</button></div>' +
      '<pre class="log" id="lg-pre"><div class="loading"><span class="spinner"></span>加载中…</div></pre>';

    var rawLines = [];
    var timer = null;

    function apply() {
      var pre = document.getElementById('lg-pre');
      var kw = document.getElementById('lg-filter').value.trim().toLowerCase();
      var lines = kw ? rawLines.filter(function (l) { return l.toLowerCase().indexOf(kw) >= 0; }) : rawLines;
      document.getElementById('lg-count').textContent =
        lines.length + ' 行' + (kw ? ' / 共 ' + rawLines.length + ' 行' : '');
      pre.textContent = lines.length ? lines.join('\n') : '（无匹配行）';
    }
    function load() {
      api('/admin/api/logs?n=500').then(function (d) {
        if (!d || !d.ok) {
          document.getElementById('lg-sub').textContent = '加载失败：' + ((d && d.err) || '未知错误');
          return;
        }
        rawLines = d.lines || [];
        apply();
      });
    }
    document.getElementById('lg-refresh').addEventListener('click', load);
    document.getElementById('lg-filter').addEventListener('input', apply);
    document.getElementById('lg-bottom').addEventListener('click', function () {
      var pre = document.getElementById('lg-pre');
      pre.scrollTop = pre.scrollHeight;
    });
    document.getElementById('lg-auto').addEventListener('change', function () {
      if (timer) { clearInterval(timer); timer = null; }
      if (this.checked) {
        timer = setInterval(function () { if (!document.hidden) load(); }, 3000);
      }
    });
    load();
    return {
      reload: load,
      destroy: function () { if (timer) clearInterval(timer); }
    };
  }

  // ==================== 启动 ====================
  var VIEWS = {
    overview: viewOverview,
    accounts: viewAccounts,
    gateways: viewGateways,
    settings: viewSettings,
    logs: viewLogs
  };

  function boot() {
    // 兼容旧表单跳转带来的提示与 tab
    var qs = new URLSearchParams(location.search);
    var msg = qs.get('msg'), err = qs.get('err'), tab = qs.get('tab');
    if (msg) setTimeout(function () { toast(msg, 'ok'); }, 300);
    if (err) setTimeout(function () { toast(err, 'err'); }, 300);
    if (tab && !location.hash) location.hash = '#/' + tab;
    api('/admin/api/whoami').then(function (d) {
      if (d && d.ok && d.csrf) {
        CSRF = d.csrf;
        showApp();
        route();
      } else {
        showLogin();
      }
    });
  }
  boot();
})();
