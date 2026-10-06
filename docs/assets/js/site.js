/* subenum site behaviour. No dependencies; every feature degrades to plain HTML. */
(function () {
  'use strict';

  var root = document.documentElement;
  var reduceMotion = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }

  /* ---------- Theme ---------- */

  function syncThemeLabel() {
    var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    $$('[data-theme-toggle]').forEach(function (b) { b.setAttribute('aria-label', 'Switch to ' + next + ' theme'); });
  }

  $$('[data-theme-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('subenum-theme', next); } catch (e) {}
      syncThemeLabel();
    });
  });
  syncThemeLabel();

  /* ---------- Modal helpers (drawer and search) ---------- */

  var lastFocus = null;

  function openLayer(el, focusTarget) {
    lastFocus = document.activeElement;
    el.hidden = false;
    document.body.style.overflow = 'hidden';
    (focusTarget || el.querySelector('button, a, input')).focus();
  }

  function closeLayer(el) {
    if (el.hidden) return;
    el.hidden = true;
    document.body.style.overflow = '';
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  /* ---------- Drawer ---------- */

  var drawer = $('#drawer');
  var menuBtn = $('[data-menu-open]');
  if (drawer && menuBtn) {
    menuBtn.addEventListener('click', function () {
      menuBtn.setAttribute('aria-expanded', 'true');
      openLayer(drawer, $('[aria-current="page"]', drawer) || $('a', drawer));
    });
    $$('[data-menu-close]', drawer).forEach(function (el) {
      el.addEventListener('click', function () {
        menuBtn.setAttribute('aria-expanded', 'false');
        closeLayer(drawer);
      });
    });
  }

  /* ---------- Tabs ---------- */

  $$('[data-tabs]').forEach(function (group) {
    var tabs = $$('[role="tab"]', group);
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (tab, i) {
      tab.addEventListener('click', function () { select(tab, false); });
      tab.addEventListener('keydown', function (e) {
        var j = null;
        if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
        if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
        if (e.key === 'Home') j = 0;
        if (e.key === 'End') j = tabs.length - 1;
        if (j !== null) { e.preventDefault(); select(tabs[j], true); }
      });
    });
  });

  /* ---------- Code blocks: copy buttons ---------- */

  $$('pre').forEach(function (pre) {
    if (pre.closest('.console') || pre.closest('.notfound')) return;
    var host = pre.parentNode.classList && pre.parentNode.classList.contains('highlight') ? pre.parentNode : pre;
    var wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    host.parentNode.insertBefore(wrap, host);
    wrap.appendChild(host);

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy code');
    wrap.appendChild(btn);

    btn.addEventListener('click', function () {
      var text = (pre.querySelector('code') || pre).innerText.replace(/\n$/, '');
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'Copied';
        btn.classList.add('is-done');
        setTimeout(function () {
          btn.textContent = 'Copy';
          btn.classList.remove('is-done');
        }, 1800);
      });
    });
  });

  /* ---------- Docs: tables, heading anchors, table of contents ---------- */

  var body = $('[data-doc-body]');
  if (body) {
    $$('table', body).forEach(function (t) {
      var wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      t.parentNode.insertBefore(wrap, t);
      wrap.appendChild(t);
    });

    var heads = $$('h2[id], h3[id]', body);
    heads.forEach(function (h) {
      var a = document.createElement('a');
      a.className = 'anchor';
      a.href = '#' + h.id;
      a.setAttribute('aria-label', 'Link to ' + h.textContent);
      a.textContent = '#';
      h.insertBefore(a, h.firstChild);
    });

    var toc = $('[data-toc]');
    var list = $('[data-toc-list]');
    if (toc && list && heads.length > 2) {
      var links = heads.map(function (h) {
        var li = document.createElement('li');
        li.className = h.tagName === 'H3' ? 'l3' : 'l2';
        var a = document.createElement('a');
        a.href = '#' + h.id;
        a.textContent = h.textContent.replace(/^#/, '');
        li.appendChild(a);
        list.appendChild(li);
        return a;
      });
      toc.hidden = false;

      if ('IntersectionObserver' in window) {
        var visible = {};
        var io = new IntersectionObserver(function (entries) {
          entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
          var current = null;
          for (var i = 0; i < heads.length; i++) {
            if (visible[heads[i].id]) { current = i; break; }
          }
          if (current === null) return;
          links.forEach(function (a, i) { a.classList.toggle('is-active', i === current); });
        }, { rootMargin: '-60px 0px -60% 0px' });
        heads.forEach(function (h) { io.observe(h); });
      }
    }
  }

  /* ---------- Search ---------- */

  var search = $('[data-search]');
  var input = $('[data-search-input]');
  var results = $('[data-search-results]');
  var empty = $('[data-search-empty]');
  var index = null;
  var active = -1;

  function loadIndex() {
    if (index) return Promise.resolve(index);
    return fetch(window.SUBENUM.searchIndex).then(function (r) { return r.json(); }).then(function (data) {
      // strip_html leaves entities such as &lt; behind; decode them once.
      var decoder = document.createElement('textarea');
      index = data.map(function (d) {
        decoder.innerHTML = d.body;
        d.body = decoder.value;
        d.lower = (d.title + ' ' + d.body).toLowerCase();
        return d;
      });
      return index;
    });
  }

  function escapeHTML(s) {
    return s.replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function highlight(text, terms) {
    var out = escapeHTML(text);
    terms.forEach(function (t) {
      var re = new RegExp('(' + escapeHTML(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
      out = out.replace(re, '<mark>$1</mark>');
    });
    return out;
  }

  function runSearch(q) {
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    results.innerHTML = '';
    active = -1;
    if (!terms.length) { empty.hidden = true; return; }

    var hits = index.filter(function (d) {
      return terms.every(function (t) { return d.lower.indexOf(t) !== -1; });
    }).map(function (d) {
      var score = 0;
      var title = d.title.toLowerCase();
      terms.forEach(function (t) {
        if (title.indexOf(t) !== -1) score += 20;
        score += Math.min(d.lower.split(t).length - 1, 10);
      });
      return { d: d, score: score };
    }).sort(function (a, b) { return b.score - a.score; }).slice(0, 8);

    empty.hidden = hits.length > 0;
    if (!hits.length) {
      empty.textContent = 'Nothing matches “' + q + '”. Try a flag name such as -rate, or a word like wildcard.';
      return;
    }

    hits.forEach(function (h) {
      var bodyLower = h.d.body.toLowerCase();
      var at = bodyLower.indexOf(terms[0]);
      var url = h.d.url;
      var snippet = h.d.body.slice(0, 140);
      if (at !== -1) {
        var start = Math.max(0, at - 60);
        snippet = (start > 0 ? '…' : '') + h.d.body.slice(start, at + 100).trim() + '…';
        // Scroll-to-text: point at the whole word around the first match.
        var ws = at, we = at + terms[0].length;
        while (ws > 0 && /[\w-]/.test(h.d.body[ws - 1])) ws--;
        while (we < h.d.body.length && /[\w-]/.test(h.d.body[we])) we++;
        url += '#:~:text=' + encodeURIComponent(h.d.body.slice(ws, we)).replace(/-/g, '%2D');
      }
      var li = document.createElement('li');
      li.innerHTML = '<a href="' + escapeHTML(url) + '"><span class="r-title">' + escapeHTML(h.d.title) +
        '</span><span class="r-section">' + escapeHTML(h.d.section) + '</span>' +
        '<span class="r-snippet">' + highlight(snippet, terms) + '</span></a>';
      results.appendChild(li);
    });
    setActive(0);
  }

  function setActive(i) {
    var links = $$('a', results);
    if (!links.length) return;
    active = (i + links.length) % links.length;
    links.forEach(function (a, j) {
      a.classList.toggle('is-active', j === active);
      if (j === active) a.scrollIntoView({ block: 'nearest' });
    });
  }

  function openSearch() {
    if (!search) return;
    openLayer(search, input);
    input.select();
    loadIndex().then(function () { if (input.value) runSearch(input.value); }).catch(function () {
      empty.hidden = false;
      empty.textContent = 'Search could not load. Check your connection and try again.';
    });
  }

  if (search) {
    $$('[data-search-open]').forEach(function (b) { b.addEventListener('click', openSearch); });
    $$('[data-search-close]').forEach(function (b) { b.addEventListener('click', function () { closeLayer(search); }); });
    input.addEventListener('input', function () {
      if (index) runSearch(input.value);
      else loadIndex().then(function () { runSearch(input.value); });
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1); }
      if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
      if (e.key === 'Enter') {
        var a = $$('a', results)[active];
        if (a) { e.preventDefault(); window.location.href = a.href; }
      }
    });
  }

  document.addEventListener('keydown', function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) || document.activeElement.isContentEditable;
    if ((e.key === '/' && !typing) || (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey))) {
      if (search && search.hidden) { e.preventDefault(); openSearch(); }
    }
    if (e.key === 'Escape') {
      if (search && !search.hidden) closeLayer(search);
      if (drawer && !drawer.hidden) {
        menuBtn.setAttribute('aria-expanded', 'false');
        closeLayer(drawer);
      }
    }
  });

  /* ---------- Home: the scan console ---------- */

  var consoleEl = $('[data-console]');
  if (consoleEl && !reduceMotion && window.requestAnimationFrame) {
    var lines = $$('.console-out li', consoleEl);
    var counters = $$('[data-count]', consoleEl).map(function (el) {
      return { el: el, to: +el.getAttribute('data-count') };
    });
    var progress = $('[data-progress]', consoleEl);
    var verdict = $('[data-verdict]', consoleEl);
    var replay = $('[data-replay]', consoleEl);
    var DURATION = 3600;

    var fmt = function (n) { return n.toLocaleString('en-US'); };

    var play = function () {
      replay.hidden = true;
      consoleEl.classList.add('is-running');
      verdict.classList.remove('is-in');
      lines.forEach(function (li) { li.classList.remove('is-in'); });
      var t0 = null;
      var step = function (now) {
        if (t0 === null) t0 = now;
        var p = Math.min((now - t0) / DURATION, 1);
        var eased = 1 - Math.pow(1 - p, 2);
        counters.forEach(function (c) { c.el.textContent = fmt(Math.round(c.to * eased)); });
        progress.style.setProperty('--p', eased);
        lines.forEach(function (li) {
          if (p >= +li.getAttribute('data-at')) li.classList.add('is-in');
        });
        if (p < 1) {
          requestAnimationFrame(step);
        } else {
          verdict.classList.add('is-in');
          replay.hidden = false;
        }
      };
      requestAnimationFrame(step);
    };

    replay.addEventListener('click', play);
    // On narrow screens the console sits below the fold: start when it is seen.
    if ('IntersectionObserver' in window) {
      consoleEl.classList.add('is-running');
      var seen = new IntersectionObserver(function (entries) {
        if (entries[0].isIntersecting) { seen.disconnect(); play(); }
      }, { threshold: 0.35 });
      seen.observe(consoleEl);
    } else {
      play();
    }
  }

  /* ---------- 404: echo the missing path ---------- */

  var missing = $('[data-path]');
  if (missing) {
    var path = window.location.pathname.replace(/^\/subenum\/?/, '').replace(/\.html$/, '').replace(/[^\w.-]+/g, '.').replace(/^\.+|\.+$/g, '');
    if (path) missing.textContent = path.slice(0, 48);
  }
})();
