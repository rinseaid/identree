package server

import (
	"html/template"
	"strings"
	"time"
)

// templateFuncMap is the shared function map for all templates.
var templateFuncMap = template.FuncMap{
	"formatDuration": func(d time.Duration) string { return formatDuration(T("en"), d) },
	"formatTime":     formatTime,
	"eqInt":          func(a, b int) bool { return a == b },
	"add":            func(a, b int) int { return a + b },
	"sub":            func(a, b int) int { return a - b },
	"splitCommaTemplate": func(s string) []string {
		var out []string
		for _, v := range strings.Split(s, ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	},
}

// Pre-parsed templates — avoids re-parsing on every request.
var (
	approvalAlreadyTmpl = template.Must(template.New("already").Parse(approvalAlreadyHTML))
	approvalExpiredTmpl = template.Must(template.New("expired").Parse(approvalExpiredHTML))
	adminTmpl           = template.Must(template.New("admin").Funcs(templateFuncMap).Parse(adminPageHTML))
	accessTmpl          = template.Must(template.New("access").Funcs(templateFuncMap).Parse(accessPageHTML))
	dashboardTmpl       = template.Must(template.New("dashboard").Funcs(templateFuncMap).Parse(dashboardHTML))
	historyTmpl         = template.Must(template.New("history").Funcs(templateFuncMap).Parse(historyPageHTML))
)
// HTML templates
// All user-controlled values are rendered via html/template (auto-escaped).
// Templates share a common CSS design system with dark mode support via
// CSS custom properties and @media (prefers-color-scheme: dark).

// sharedCSS is the common design system embedded in every template.
const sharedCSS = `
    :root {
      --bg: #f5f4f9;
      --surface: #ffffff;
      --surface-2: #efecf8;
      --text: #100f18;
      --text-2: #635e80;
      --text-3: #736e91;
      --border: #e2dff2;
      --primary: #7c3aed;
      --primary-h: #6d28d9;
      --primary-fg: #ffffff;
      --primary-sub: #f2eefe;
      --success: #059669;
      --success-bg: #ecfdf5;
      --success-border: #a7f3d0;
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --danger-border: #fecaca;
      --warning: #c2810a;
      --warning-bg: #fffbeb;
      --warning-border: #fde68a;
      --code-bg: #f0edfb;
      --code-border: #ddd8f5;
      --terminal-bg: #100f18;
      --terminal-text: #a8f0b4;
      --focus-ring: 0 0 0 3px rgba(124,58,237,0.28);
      --chip-cmd-bg: rgba(124,58,237,0.08); --chip-cmd-border: rgba(124,58,237,0.20);
      --chip-host-bg: rgba(5,150,105,0.08); --chip-host-border: rgba(5,150,105,0.20);
      --chip-all-bg: rgba(217,70,239,0.09); --chip-all-text: #a21caf; --chip-all-border: rgba(217,70,239,0.20);
      --info-bg: #eff6ff; --info-border: #bfdbfe;
      /* typographic scale — use these instead of bare font-size values */
      --fs-2xs: 0.625rem;   /* 10px */
      --fs-xs:  0.6875rem;  /* 11px */
      --fs-sm:  0.75rem;    /* 12px */
      --fs-md:  0.8125rem;  /* 13px */
      --fs-base: 0.875rem;  /* 14px */
      --fs-lg:  1rem;       /* 16px */
      --fs-xl:  1.0625rem;  /* 17px */
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #07060e;
        --surface: #100e1e;
        --surface-2: #1d1a32;
        --text: #f0eeff;
        --text-2: #9b97c4;
        --text-3: #9590b8;
        --border: #2a2647;
        --primary: #c084fc;
        --primary-h: #a855f7;
        --primary-fg: #ffffff;
        --primary-sub: rgba(192,132,252,0.18);
        --success: #34d399;
        --success-bg: #031510;
        --success-border: #064e3b;
        --danger: #f87171;
        --danger-bg: #180808;
        --danger-border: #7f1d1d;
        --warning: #fbbf24;
        --warning-bg: #120a01;
        --warning-border: #78350f;
        --code-bg: #100e1e;
        --code-border: #2a2647;
        --focus-ring: 0 0 0 3px rgba(192,132,252,0.35);
        --chip-cmd-bg: rgba(192,132,252,0.13); --chip-cmd-border: rgba(192,132,252,0.28);
        --chip-host-bg: rgba(52,211,153,0.10); --chip-host-border: rgba(52,211,153,0.22);
        --chip-all-bg: rgba(232,121,249,0.12); --chip-all-text: #e879f9; --chip-all-border: rgba(232,121,249,0.25);
        --info-bg: #0d1829; --info-border: #1e3a5f;
      }
    }
    .theme-light {
      --bg: #f4f2fb; --surface: #ffffff; --surface-2: #ebe8f8;
      --text: #0e0d1a; --text-2: #5a5578; --text-3: #736e91;
      --border: #dbd8f0; --primary: #7c3aed; --primary-h: #6d28d9;
      --primary-fg: #ffffff; --primary-sub: #ede9fd;
      --success: #059669; --success-bg: #ecfdf5; --success-border: #a7f3d0;
      --danger: #dc2626; --danger-bg: #fef2f2; --danger-border: #fecaca;
      --warning: #c2810a; --warning-bg: #fffbeb; --warning-border: #fde68a;
      --code-bg: #f0edfb; --code-border: #ddd8f5;
      --focus-ring: 0 0 0 3px rgba(124,58,237,0.28);
      --chip-cmd-bg: rgba(124,58,237,0.08); --chip-cmd-border: rgba(124,58,237,0.20);
      --chip-host-bg: rgba(5,150,105,0.08); --chip-host-border: rgba(5,150,105,0.20);
      --chip-all-bg: rgba(217,70,239,0.09); --chip-all-text: #a21caf; --chip-all-border: rgba(217,70,239,0.20);
      --info-bg: #eff6ff; --info-border: #bfdbfe;
    }
    .theme-dark {
      --bg: #07060e; --surface: #100e1e; --surface-2: #1d1a32;
      --text: #f0eeff; --text-2: #9b97c4; --text-3: #9590b8;
      --border: #2a2647; --primary: #c084fc; --primary-h: #a855f7;
      --primary-fg: #ffffff; --primary-sub: rgba(192,132,252,0.18);
      --success: #34d399; --success-bg: #031510; --success-border: #064e3b;
      --danger: #f87171; --danger-bg: #180808; --danger-border: #7f1d1d;
      --warning: #fbbf24; --warning-bg: #120a01; --warning-border: #78350f;
      --code-bg: #100e1e; --code-border: #2a2647;
      --focus-ring: 0 0 0 3px rgba(192,132,252,0.35);
      --chip-cmd-bg: rgba(192,132,252,0.13); --chip-cmd-border: rgba(192,132,252,0.28);
      --chip-host-bg: rgba(52,211,153,0.10); --chip-host-border: rgba(52,211,153,0.22);
      --chip-all-bg: rgba(232,121,249,0.12); --chip-all-text: #e879f9; --chip-all-border: rgba(232,121,249,0.25);
      --info-bg: #0d1829; --info-border: #1e3a5f;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 32px 16px;
    }
    /* Centered card (approval/error pages) */
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 48px 36px;
      width: 100%;
      max-width: 420px;
      text-align: center;
      box-shadow: 0 4px 24px rgba(16,15,24,0.08), 0 1px 3px rgba(16,15,24,0.05);
    }
    h2 { font-size: 1.25rem; font-weight: 700; margin: 16px 0 8px; letter-spacing: -0.02em; }
    p { margin: 8px 0; color: var(--text-2); font-size: 0.9375rem; }
    .icon {
      width: 56px; height: 56px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 8px; font-size: 1.5rem;
    }
    strong { color: var(--text); font-weight: 600; }
    /* App layout — sidebar + main */
    body.app {
      display: grid;
      grid-template-columns: 240px 1fr;
      grid-template-rows: 100vh;
      align-items: stretch;
      justify-content: stretch;
      padding: 0;
      height: 100vh;
      overflow: hidden;
    }
    @media (max-width: 768px) {
      body.app {
        grid-template-columns: 1fr;
        grid-template-rows: auto 1fr;
        height: 100dvh;
      }
    }
    /* Sidebar */
    .sidebar {
      background: var(--surface);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: visible;
      position: sticky;
      top: 0;
    }
    @media (max-width: 768px) {
      .sidebar {
        height: auto;
        border-right: none;
        border-bottom: 1px solid var(--border);
        position: static;
        flex-direction: row;
        overflow-y: visible;
        overflow-x: auto;
      }
    }
    .sidebar-brand {
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 18px 16px 14px;
      font-size: 0.9375rem;
      font-weight: 700;
      letter-spacing: -0.015em;
      color: var(--text);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    .sidebar-brand svg { color: var(--primary); flex-shrink: 0; }
    @media (max-width: 768px) {
      .sidebar-brand { border-bottom: none; border-right: 1px solid var(--border); padding: 12px 16px; }
    }
    .sidebar-nav {
      flex: 1;
      min-height: 0;
      overflow-y: auto;
      padding: 10px 8px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    @media (max-width: 768px) {
      .sidebar-nav { flex-direction: row; padding: 8px; overflow-x: auto; gap: 2px; }
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 500;
      color: var(--text-2);
      text-decoration: none;
      transition: background 0.12s, color 0.12s;
      white-space: nowrap;
    }
    .nav-item:hover { background: var(--surface-2); color: var(--text); }
    .nav-item.active {
      background: var(--primary);
      color: #fff;
      font-weight: 700;
      box-shadow: 0 2px 12px rgba(192,132,252,0.35);
    }
    .nav-item svg { width: 17px; height: 17px; flex-shrink: 0; opacity: 0.7; }
    .nav-item.active svg { opacity: 1; }
    .nav-badge { margin-left: auto; min-width: 18px; padding: 1px 5px; border-radius: 9px; font-size: 0.7rem; font-weight: 700; background: var(--primary); color: #fff; text-align: center; line-height: 1.5; }
    .nav-item.active .nav-badge { background: rgba(255,255,255,0.3); }
    .sidebar-sub { display: flex; flex-direction: column; gap: 1px; padding: 2px 0 6px 22px; }
    .sub-item {
      display: flex; align-items: center; gap: 6px;
      padding: 6px 12px;
      border-radius: 7px;
      font-size: 0.9375rem;
      color: var(--text-3); text-decoration: none;
      font-weight: 500; transition: background 0.1s, color 0.1s;
      white-space: nowrap;
    }
    .sub-item svg { width: 13px; height: 13px; flex-shrink: 0; opacity: 0.7; }
    .sub-item:hover { background: var(--surface-2); color: var(--text-2); }
    .sub-item.active { color: var(--primary); font-weight: 700; background: var(--primary-sub); }
    .sub-item.active svg { opacity: 1; }
    @media (max-width: 768px) {
      .sidebar-sub { flex-direction: row; padding: 4px 4px 4px 8px; overflow-x: auto; gap: 2px; }
      .sub-item { white-space: nowrap; }
    }
    .sidebar-footer {
      padding: 8px;
      border-top: 1px solid var(--border);
      flex-shrink: 0;
    }
    @media (max-width: 768px) {
      .sidebar-footer { border-top: none; border-left: 1px solid var(--border); padding: 8px; }
    }
    .user-btn {
      display: flex; align-items: center; gap: 9px; width: 100%;
      padding: 7px 10px; border-radius: 7px; background: none;
      border: none; cursor: pointer; text-align: left;
      color: var(--text); font-family: inherit; font-size: 0.8125rem;
      font-weight: 500; position: relative;
    }
    .user-btn:hover { background: var(--surface-2); }
    .user-btn-chevron { margin-left: auto; color: var(--text-3); font-size: 0.75rem; line-height: 1; transition: transform 0.15s; flex-shrink: 0; }
    .user-btn.open .user-btn-chevron { transform: rotate(180deg); }
    .user-avatar {
      width: 26px; height: 26px; border-radius: 50%;
      background: var(--primary); color: var(--primary-fg);
      font-size: 0.6875rem; font-weight: 700;
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }
    .user-avatar img { width: 26px; height: 26px; border-radius: 50%; object-fit: cover; }
    .user-name-wrap { min-width: 0; }
    .user-display-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 140px; }
    .user-role-badge {
      display: inline-block; font-size: 0.5625rem; padding: 1px 5px;
      border-radius: 6px; background: var(--primary); color: var(--primary-fg);
      font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; vertical-align: middle; margin-left: 5px;
    }
    .user-dropdown {
      display: none; position: absolute; bottom: calc(100% + 4px); left: 0; right: 0;
      background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
      box-shadow: 0 8px 24px rgba(16,15,24,0.14), 0 2px 6px rgba(16,15,24,0.08);
      padding: 8px 0; z-index: 200; min-width: 200px;
    }
    @media (max-width: 768px) {
      .user-dropdown { bottom: auto; top: calc(100% + 4px); left: auto; right: 0; min-width: 220px; }
    }
    .user-btn.open .user-dropdown { display: block; }
    .user-dropdown-label {
      padding: 3px 14px; font-size: 0.6875rem; color: var(--text-3);
      font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px;
    }
    .user-dropdown-item {
      display: block; padding: 7px 14px; color: var(--text);
      text-decoration: none; font-size: 0.8125rem; font-weight: 500;
    }
    .user-dropdown-item:hover { background: var(--surface-2); }
    .user-dropdown-divider { border-top: 1px solid var(--border); margin: 6px 0; }
    .user-dropdown select {
      margin: 3px 14px; padding: 4px 8px; border: 1px solid var(--border);
      border-radius: 6px; font-size: 0.75rem; background: var(--surface); color: var(--text);
      width: calc(100% - 28px);
    }
    .theme-opts { display: flex; gap: 3px; padding: 4px 14px 6px; }
    .theme-opt {
      flex: 1; text-align: center; padding: 4px 6px; border-radius: 5px;
      font-size: 0.6875rem; color: var(--text-2); text-decoration: none;
      border: 1px solid var(--border); cursor: pointer; font-weight: 500;
    }
    .theme-opt:hover { background: var(--surface-2); }
    .theme-opt.active { background: var(--primary); color: var(--primary-fg); border-color: var(--primary); font-weight: 700; }
    /* Main content area */
    .main {
      height: 100vh;
      overflow-y: auto;
      background: var(--bg);
      padding: 32px 36px;
    }
    @media (max-width: 768px) {
      .main { height: auto; padding: 20px 16px; }
    }
    @media (max-width: 480px) {
      .main { padding: 16px 12px; }
    }
    /* Page header */
    .page-hd {
      display: flex; align-items: center; justify-content: space-between;
      gap: 16px; margin-bottom: 32px; flex-wrap: wrap;
    }
    .page-hd h1 {
      font-size: 1.375rem; font-weight: 700; letter-spacing: -0.03em;
      color: var(--text);
    }
    .page-hd-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    /* Section label */
    .slabel {
      font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.09em; color: var(--text-3); margin: 32px 0 12px;
    }
    .slabel.warn { color: var(--warning); }
    /* List rows */
    .list { display: flex; flex-direction: column; gap: 2px; }
    .row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 16px 16px; border-radius: 10px; gap: 16px;
      border-left: 3px solid transparent;
      margin: 0 -16px;
    }
    .row:hover { background: var(--surface-2); }
    .row.row-active { border-left-color: var(--primary); }
    .row-info { min-width: 0; flex: 1; }
    .row-host { font-weight: 700; font-size: 1.0625rem; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-sub { color: var(--text-2); font-size: 0.875rem; display: block; margin-top: 2px; }
    .row-label { font-size: 0.6875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-3); }
    .row-value { color: var(--text); font-weight: 500; }
    .row-code { color: var(--text-3); font-size: 0.875rem; font-family: monospace; display: block; margin-top: 2px; }
    .row-active-text { color: var(--success); font-size: 0.875rem; font-weight: 600; display: block; margin-top: 2px; }
    /* Banner */
    .banner {
      padding: 12px 16px; border-radius: 10px; margin-bottom: 16px;
      font-size: 0.9375rem; font-weight: 600; text-align: left;
    }
    .banner-success { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }
    .banner-error { background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); }
    .banner-warning { background: var(--warning-bg); border: 1px solid var(--warning-border); color: var(--warning); }
    /* Buttons */
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      padding: 8px 16px; border-radius: 8px; font-size: 0.875rem; font-weight: 600;
      border: 1px solid var(--border); background: var(--surface); color: var(--text-2);
      cursor: pointer; white-space: nowrap; text-decoration: none; font-family: inherit;
      line-height: 1.4; transition: background 0.1s, color 0.1s, border-color 0.1s;
      min-height: 34px;
    }
    .btn:hover { background: var(--surface-2); color: var(--text); border-color: var(--border); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
    .btn-primary { background: var(--primary); border-color: var(--primary); color: var(--primary-fg); }
    .btn-primary:hover { background: var(--primary-h); border-color: var(--primary-h); color: var(--primary-fg); }
    .btn-success { background: var(--success); border-color: var(--success); color: #fff; }
    .btn-success:hover { opacity: 0.88; color: #fff; }
    .btn-danger { background: var(--danger); border-color: var(--danger); color: #fff; }
    .btn-danger:hover { opacity: 0.88; color: #fff; }
    .btn-sm { padding: 6px 12px; font-size: 0.8125rem; border-radius: 7px; min-height: 30px; }
    .btn-ghost { background: none; border-color: transparent; color: var(--text-2); }
    .btn-ghost:hover { background: var(--surface-2); border-color: var(--border); color: var(--text); }
    /* Segment button */
    .seg-btn { display: inline-flex; border-radius: 8px; overflow: hidden; border: 1px solid var(--primary); flex-shrink: 0; }
    .seg-btn button, .seg-btn a {
      background: none; border: none; border-right: 1px solid var(--primary);
      padding: 7px 12px; cursor: pointer; color: var(--primary);
      font-size: 0.8125rem; font-weight: 600; font-family: inherit; line-height: 1.4;
      text-decoration: none; display: inline-flex; align-items: center;
    }
    .seg-btn button:last-child, .seg-btn a:last-child { border-right: none; }
    .seg-btn button:hover, .seg-btn a:hover { background: var(--primary); color: var(--primary-fg); }
    .seg-btn button.active, .seg-btn a.active { background: var(--primary); color: var(--primary-fg); }
    /* Elevate dropdown */
    .elevate-wrap { position: relative; display: inline-block; }
    .elevate-menu { position: fixed; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 4px; z-index: 10000; display: none; flex-direction: row; gap: 2px; box-shadow: 0 4px 16px rgba(0,0,0,0.15); }
    .elevate-menu.open { display: flex; }
    .elevate-menu button { display: inline-block; width: auto; padding: 5px 10px; border: none; background: none; color: var(--text); font-size: 0.8125rem; font-weight: 500; text-align: center; cursor: pointer; border-radius: 5px; font-family: inherit; white-space: nowrap; }
    .elevate-menu button:hover { background: var(--primary-sub); color: var(--primary); }
    /* Toggle */
    .toggle-wrap { display: flex; align-items: center; gap: 7px; cursor: pointer; user-select: none; }
    .toggle-wrap span { font-size: 0.6875rem; font-weight: 600; color: var(--text-2); }
    .toggle-track { width: 36px; height: 20px; border-radius: 10px; background: var(--border); position: relative; transition: background 0.2s; flex-shrink: 0; }
    .toggle-thumb { width: 16px; height: 16px; border-radius: 50%; background: var(--surface); box-shadow: 0 1px 3px rgba(0,0,0,0.25); position: absolute; top: 2px; left: 2px; transition: left 0.2s; }
    .toggle-wrap.active .toggle-track { background: var(--primary); }
    .toggle-wrap.active .toggle-thumb { left: 18px; }
    .list.active-only [data-active="false"] { display: none; }
    /* Empty state */
    .empty-state { color: var(--text-2); margin: 20px 0; font-size: 0.875rem; }
    /* History action badges */
    .ha {
      font-size: 0.625rem; font-weight: 700; padding: 2px 6px; border-radius: 4px;
      white-space: nowrap; flex-shrink: 0; letter-spacing: 0.04em; text-transform: uppercase;
    }
    .ha.approved { background: rgba(5,150,105,0.1); color: var(--success); }
    .ha.auto_approved, .ha.extended, .ha.elevated { background: var(--primary-sub); color: var(--primary); }
    .ha.revoked, .ha.rejected { background: var(--danger-bg); color: var(--danger); }
    .ha.rotated_breakglass { border: 1px solid var(--border); color: var(--text-3); }
    /* Modals */
    .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(13,12,20,.55); z-index: 1000; overflow-y: auto; backdrop-filter: blur(2px); }
    .modal-overlay.open { display: flex; align-items: flex-start; justify-content: center; padding: 48px 16px; }
    .modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 28px; width: 100%; max-width: 520px; box-shadow: 0 16px 48px rgba(13,12,20,0.2), 0 4px 12px rgba(13,12,20,0.12); }
    .modal-box h3 { margin: 0 0 20px; font-size: 1rem; font-weight: 700; letter-spacing: -0.015em; }
    .modal-field { margin-bottom: 14px; }
    .modal-field label { display: block; font-size: 0.8125rem; font-weight: 600; margin-bottom: 5px; color: var(--text-2); }
    .modal-field input, .modal-field select { width: 100%; padding: 8px 11px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font-size: 0.875rem; font-family: inherit; outline: none; }
    .modal-field input:focus, .modal-field select:focus { border-color: var(--primary); box-shadow: var(--focus-ring); }
    .modal-field select { appearance: none; -webkit-appearance: none; background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23888' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; background-size: 12px; padding-right: 30px; cursor: pointer; }
    .modal-row { display: flex; gap: 10px; }
    .modal-row .modal-field { flex: 1; }
    .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 20px; }
    /* Admin tabs */
    .admin-tabs { display: flex; gap: 2px; margin-bottom: 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 9px; padding: 3px; overflow-x: auto; }
    .admin-tabs a { flex: 1; text-align: center; padding: 6px 10px; border-radius: 7px; font-size: 0.8125rem; font-weight: 500; color: var(--text-2); text-decoration: none; transition: background 0.1s, color 0.1s; white-space: nowrap; }
    .admin-tabs a:hover { background: var(--surface-2); color: var(--text); }
    .admin-tabs a.active { background: var(--primary); color: var(--primary-fg); font-weight: 700; }
    /* Info table */
    .info-section { margin-bottom: 28px; }
    .info-section h3 { font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.09em; color: var(--text-3); margin-bottom: 12px; }
    .info-table { width: 100%; border-collapse: collapse; }
    .info-table td { padding: 9px 12px 9px 0; border-bottom: 1px solid var(--border); font-size: 0.875rem; vertical-align: top; }
    .info-table tr:last-child td { border-bottom: none; }
    .info-label { color: var(--text-2); width: 44%; font-size: 0.8125rem; padding-right: 16px; }
    /* Deploy modal extras */
    .deploy-log { background: var(--terminal-bg); color: var(--terminal-text); font-family: monospace; font-size: 0.75rem; border-radius: 8px; padding: 12px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; margin-top: 12px; display: none; }
    .deploy-log.visible { display: block; }
    .deploy-status { font-size: 0.8125rem; font-weight: 600; margin-top: 8px; }
    .deploy-status.ok { color: var(--success); }
    .deploy-status.err { color: var(--danger); }
    .deploy-warning-banner { display: flex; gap: 10px; align-items: flex-start; background: var(--warning-bg); border: 1px solid var(--warning-border); border-radius: 10px; padding: 12px 14px; margin-bottom: 18px; }
    .deploy-warning-icon { font-size: 1rem; color: var(--warning); flex-shrink: 0; margin-top: 1px; }
    .deploy-warning-text { font-size: 0.8125rem; color: var(--text); line-height: 1.5; }
    .deploy-user-keys-label { font-size: 0.75rem; font-weight: 600; color: var(--text-2); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }
    .deploy-user-keys-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
    .deploy-key-line { font-family: monospace; font-size: 0.75rem; background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 6px; padding: 5px 10px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: default; }
    .deploy-key-line:hover { border-color: var(--primary); color: var(--primary); }
    .filter-chip { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 20px; background: var(--primary-sub); border: 1px solid var(--primary); color: var(--primary); font-size: 0.75rem; font-weight: 600; text-decoration: none; }
    .filter-chip:hover { background: var(--primary); color: var(--primary-fg); }
    .session-filter-input { padding: 4px 10px; border: 1px solid var(--border); border-radius: 20px; font-size: 0.8125rem; background: var(--surface); color: var(--text); outline: none; width: 120px; }
    .session-filter-input:focus { border-color: var(--primary); }
    .session-filter-input::placeholder { color: var(--text-3); }
    .script-preview { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 14px; overflow: hidden; }
    .script-preview-header { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; cursor: pointer; user-select: none; }
    .script-preview-header:hover { background: var(--surface-2); }
    .script-preview-label { font-size: 0.8125rem; font-weight: 600; color: var(--text-2); display: flex; align-items: center; gap: 6px; }
    .script-expand-chevron { color: var(--text-3); font-size: 0.7rem; transition: transform 0.15s; display: inline-block; }
    .script-preview.open .script-expand-chevron { transform: rotate(90deg); }
    .script-preview-body { border-top: 1px solid var(--border); max-height: 180px; overflow-y: auto; display: none; }
    .script-preview.open .script-preview-body { display: block; }
    .script-preview-body pre { margin: 0; padding: 10px 12px; font-size: 0.6875rem; font-family: monospace; white-space: pre; color: var(--text); }
    .key-upload-row { display: flex; gap: 8px; }
    .key-action-btn { display: flex; align-items: center; justify-content: center; gap: 6px; flex: 1; padding: 9px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); color: var(--text); font-size: 0.8125rem; font-weight: 600; font-family: inherit; cursor: pointer; text-align: center; box-sizing: border-box; min-height: 40px; }
    .key-action-btn:hover { border-color: var(--primary); color: var(--primary); }
    .key-info-card { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid var(--success-border); border-radius: 8px; background: var(--success-bg); margin-bottom: 8px; }
    .key-info-icon { color: var(--success); font-size: 1rem; flex-shrink: 0; }
    .key-info-text { min-width: 0; }
    .key-info-type { font-size: 0.75rem; font-weight: 700; color: var(--success); text-transform: uppercase; letter-spacing: .05em; }
    .key-info-fp { font-size: 0.75rem; font-family: monospace; color: var(--text-2); word-break: break-all; }
    .key-clear-btn { font-size: 0.75rem; color: var(--text-2); background: none; border: none; cursor: pointer; padding: 0; text-decoration: underline; }
    .key-clear-btn:hover { color: var(--text); }
    /* Sudo rules */
    .text-input { width: 100%; padding: 7px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font-size: 0.875rem; font-family: inherit; outline: none; }
    .text-input:focus { border-color: var(--primary); box-shadow: var(--focus-ring); }
    /* Chips */
    .summary-chip { font-size: 0.75rem; padding: 2px 8px; border-radius: 8px; cursor: pointer; white-space: nowrap; user-select: none; display: inline-flex; align-items: center; gap: 4px; transition: opacity 0.15s; }
    .summary-chip:hover { opacity: 0.8; }
    .summary-chip.commands { background: var(--chip-cmd-bg); color: var(--primary); border: 1px solid var(--chip-cmd-border); }
    .summary-chip.hosts { background: var(--chip-host-bg); color: var(--success); border: 1px solid var(--chip-host-border); }
    .summary-chip.all { background: var(--chip-all-bg); color: var(--chip-all-text); border: 1px solid var(--chip-all-border); cursor: default; }
    .summary-chip.single { background: var(--surface-2); color: var(--text-2); border: 1px solid var(--border); cursor: default; font-family: monospace; }
    .summary-sep { font-size: 0.625rem; color: var(--text-3); }
    .caret { font-size: 0.5rem; transition: transform 0.2s; display: inline-block; }
    .summary-chip.open .caret { transform: rotate(180deg); }
    .expanded-list { display: none; margin-top: 6px; }
    .expanded-list.visible { display: flex; flex-wrap: wrap; gap: 3px; max-width: 300px; }
    .pill { display: inline-block; font-size: 0.75rem; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }
    .pill.cmd { background: var(--surface-2); color: var(--text-2); border: 1px solid var(--border); font-family: monospace; }
    .pill.host { background: var(--chip-host-bg); color: var(--success); border: 1px solid var(--chip-host-border); }
    .pill.user { background: var(--primary-sub); color: var(--primary); border: 1px solid rgba(124,58,237,0.2); }
    a.pill { text-decoration: none; cursor: pointer; }
    a.pill:hover { opacity: 0.75; }
    .filter-clear-btn { padding: 3px 9px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text-3); cursor: pointer; font-size: 0.75rem; font-family: inherit; white-space: nowrap; line-height: 1.4; }
    .filter-clear-btn:hover { color: var(--danger); border-color: var(--danger-border); }
    .filter-toggle-btn { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border: 1px solid var(--border); border-radius: 5px; background: none; color: var(--text-3); cursor: pointer; font-size: 0.75rem; font-family: inherit; white-space: nowrap; line-height: 1.4; }
    .filter-toggle-btn:hover { color: var(--text); border-color: var(--text-3); }
    .filter-toggle-btn.active { color: var(--primary); border-color: var(--primary); background: var(--primary-sub); }
    .group-badge { display: inline-block; font-size: 0.75rem; padding: 2px 8px; border-radius: 8px; background: var(--surface-2); color: var(--text-2); white-space: nowrap; margin-right: 3px; margin-bottom: 2px; text-decoration: none; border: 1px solid var(--border); }
    .group-badge-link:hover { background: var(--primary); color: var(--primary-fg); border-color: var(--primary); }
    /* Pill overflow */
    .pill-cell { display: flex; flex-wrap: nowrap; overflow: clip; gap: 4px; align-items: center; min-width: 0; }
    .pill-more-btn { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 8px; background: var(--surface-2); color: var(--text-3); border: 1px solid var(--border); font-size: 0.75rem; cursor: pointer; white-space: nowrap; font-family: inherit; }
    .pill-more-btn:hover { background: var(--primary-sub); color: var(--primary); border-color: var(--primary); }
    .pagination-bar { display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 12px; font-size: 0.8125rem; flex-wrap: wrap; }
    .pagination-btn { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface); color: var(--text-2); cursor: pointer; font-size: 0.8125rem; font-family: inherit; line-height: 1.4; }
    .pagination-btn:hover:not([disabled]) { background: var(--surface-2); color: var(--text); }
    .pagination-btn[disabled] { opacity: 0.4; cursor: default; }
    .pagination-info { color: var(--text-2); font-size: 0.8125rem; }
    .pagination-size-select { padding: 3px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.8125rem; background: var(--surface); color: var(--text); cursor: pointer; font-family: inherit; }
    .admin-req { font-size: 0.6875rem; padding: 2px 7px; border-radius: 5px; background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); white-space: nowrap; font-weight: 600; }
    /* Bulk actions row */
    .bulk-row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 12px; flex-wrap: wrap; }
    /* Hosts toolbar */
    .hosts-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    /* Host rows */
    .host-row-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .host-row-info { min-width: 0; flex: 1; display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
    .host-row-actions { display: flex; gap: 6px; flex-shrink: 0; align-items: center; }
    .host-row-users { margin-top: 10px; padding: 8px 0 4px 16px; border-left: 2px solid var(--border); }
    .session-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; }
    .session-actions { display: flex; gap: 6px; flex-shrink: 0; }
    /* User card */
    .user-card-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 0.8125rem; color: var(--text-2); padding: 4px 0 0; }
    .meta-sessions-link { color: var(--primary); font-weight: 600; text-decoration: none; }
    .meta-sessions-link:hover { text-decoration: underline; }
    .row-card { padding: 10px 16px; }
    /* Group card */
    .group-card-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 0.875rem; padding: 4px 0; }
    .group-card-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-3); white-space: nowrap; }
    .col-sort-link { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-3); text-decoration: none; }
    .col-sort-link:hover, .col-sort-link.active { color: var(--primary); }
    .groups-table { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .groups-table-header { display: grid; grid-template-columns: 200px 1.2fr 1.0fr 1.4fr 1.0fr; gap: 0; padding: 8px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .groups-table-filter { display: grid; grid-template-columns: 200px 1.2fr 1.0fr 1.4fr 1.0fr; gap: 0; padding: 5px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .groups-table-row { display: grid; grid-template-columns: 200px 1.2fr 1.0fr 1.4fr 1.0fr; gap: 0; padding: 10px 12px; border-bottom: 1px solid var(--border); align-items: center; }
    .groups-table-row:last-child { border-bottom: none; }
    .groups-table-row:hover { background: var(--surface-2); }
    .gtcol { display: flex; align-items: flex-start; padding: 0 6px; min-width: 0; }
    .gtcol-filter-input { width: 100%; padding: 4px 7px; border: 1px solid var(--border); border-radius: 5px; font-size: 0.75rem; background: var(--bg); color: var(--text); box-sizing: border-box; outline: none; }
    .gtcol-filter-input:focus { border-color: var(--primary); }
    .gtcol-filter-wrap { padding: 0 6px; min-width: 0; width: 100%; }
    /* Users table */
    .users-table { display: grid; grid-template-columns: 200px 2fr auto; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .users-table-header { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; gap: 0; background: var(--surface-2); border-bottom: 1px solid var(--border); align-items: center; }
    .users-table-header > .gtcol { padding: 8px 0; }
    .users-table-header > .gtcol:first-child { padding-left: 12px; }
    .users-table-header > .gtcol:last-child { padding-right: 12px; }
    .users-table-filter { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; gap: 0; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .users-table-filter > * { padding: 5px 0; }
    .users-table-filter > *:first-child { padding-left: 6px; }
    .users-table-filter > *:last-child { padding-right: 6px; }
    .users-table-row { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; gap: 0; border-bottom: 1px solid var(--border); align-items: center; }
    .users-table-row > .gtcol { padding: 10px 0; }
    .users-table-row > .gtcol:first-child { padding-left: 12px; }
    .users-table-row > .gtcol:last-child { padding-right: 12px; }
    .users-table-row:last-child { border-bottom: none; }
    .users-table-row:hover { background: var(--surface-2); }
    /* Hosts table */
    .hosts-table { display: grid; grid-template-columns: 200px 2fr auto; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .hosts-table-header { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; gap: 0; background: var(--surface-2); border-bottom: 1px solid var(--border); align-items: center; }
    .hosts-table-header > .gtcol { padding: 8px 0; }
    .hosts-table-header > .gtcol:first-child { padding-left: 12px; }
    .hosts-table-header > .gtcol:last-child { padding-right: 12px; }
    .hosts-table-filter { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; gap: 0; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .hosts-table-filter > * { padding: 5px 0; }
    .hosts-table-filter > *:first-child { padding-left: 6px; }
    .hosts-table-filter > *:last-child { padding-right: 6px; }
    .hosts-table-row { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; gap: 0; border-bottom: 1px solid var(--border); align-items: center; }
    .hosts-table-row > .gtcol { padding: 10px 0; }
    .hosts-table-row > .gtcol:first-child { padding-left: 12px; }
    .hosts-table-row > .gtcol:last-child { padding-right: 12px; }
    .hosts-table-row:last-child { border-bottom: none; }
    .hosts-table-row:hover { background: var(--surface-2); }
    /* Session count pill */
    .session-count { display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 12px; background: var(--primary-sub); color: var(--primary); font-size: 0.8125rem; font-weight: 600; text-decoration: none; border: 1px solid rgba(124,58,237,0.18); }
    .session-count:hover { background: var(--primary); color: var(--primary-fg); }
    /* Group filter */
    .group-filter { display: flex; align-items: center; gap: 8px; font-size: 0.875rem; }
    .group-filter select { padding: 7px 11px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font-size: 0.875rem; cursor: pointer; outline: none; }
    /* Elevate form */
    .elevate-form { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
    /* Misc shared */
    .host-group { font-size: 0.75rem; padding: 3px 8px; border-radius: 6px; background: var(--primary-sub); color: var(--primary); margin-left: 6px; vertical-align: middle; border: 1px solid rgba(124,58,237,0.15); }
    .user-name { font-weight: 700; font-size: 1.0625rem; }
    .timestamp { display: inline; }
    .time-ago { display: inline; font-size: 0.8125rem; color: var(--text-2); }
    /* Claims panels */
    .claims-toggle-btn { background: none; border: 1px solid var(--border); border-radius: 5px; cursor: pointer; color: var(--text-3); font-size: 0.75rem; padding: 2px 8px; font-weight: 500; white-space: nowrap; line-height: 1.5; }
    .claims-toggle-btn:hover { background: var(--surface-2); color: var(--primary); border-color: var(--primary); }
    .claims-panel { display: none; background: var(--surface-2); border-top: 1px solid var(--border); padding: 14px 16px 16px; }
    .group-wrapper .claims-panel { border-bottom: 1px solid var(--border); }
    .user-claims-panel { grid-column: 1/-1; display: none; background: var(--surface-2); border-top: 1px solid var(--border); padding: 14px 16px 16px; }
    .claims-form { display: grid; grid-template-columns: 160px 1fr; gap: 6px 10px; align-items: start; max-width: 760px; }
    .claims-form-label { font-size: 0.8125rem; font-weight: 500; color: var(--text-3); font-family: monospace; white-space: nowrap; padding-top: 5px; }
    .claims-form-field { display: flex; flex-direction: column; gap: 2px; }
    .claims-form-field input[type=text] { width: 100%; padding: 4px 8px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text); font-size: 0.8125rem; font-family: monospace; box-sizing: border-box; }
    .claims-form-field input[type=text]:focus { border-color: var(--primary); outline: none; }
    .claims-form-field input[type=text]::placeholder { color: var(--text-3); opacity: 0.55; font-style: italic; }
    .claims-form-hint { font-size: 0.7rem; color: var(--text-3); line-height: 1.3; }
    .claims-form-actions { grid-column: 2; display: flex; gap: 8px; align-items: center; margin-top: 4px; }
    .claims-readonly { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border); font-size: 0.8125rem; color: var(--text-3); }
    .claims-readonly-row { display: flex; gap: 10px; padding: 2px 0; font-family: monospace; font-size: 0.8125rem; }
    .claims-readonly-key { color: var(--text-3); min-width: 140px; flex-shrink: 0; }
    .claims-readonly-val { color: var(--text-2); word-break: break-all; }
    .ssh-keys-list { display: flex; flex-direction: column; gap: 6px; margin-bottom: 8px; }
    .ssh-key-row { display: flex; gap: 6px; align-items: flex-start; }
    .ssh-key-row textarea { flex: 1; font-family: monospace; font-size: 0.75rem; padding: 5px 8px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text); resize: vertical; min-height: 38px; max-height: 80px; box-sizing: border-box; }
    .ssh-key-row textarea:focus { border-color: var(--primary); outline: none; }
    .ssh-key-remove { flex-shrink: 0; background: none; border: 1px solid var(--border); border-radius: 5px; cursor: pointer; color: var(--danger); padding: 3px 7px; font-size: 0.75rem; line-height: 1.4; }
    .ssh-key-remove:hover { background: var(--danger); color: #fff; }
    .ssh-keys-empty { font-size: 0.8125rem; color: var(--text-3); font-style: italic; padding: 4px 0; }
    .claims-panel-title { font-size: 0.75rem; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 10px; }
    /* Accessibility */
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
    .skip-link { position: absolute; top: -100%; left: 8px; z-index: 9999; padding: 8px 16px; background: var(--primary); color: var(--primary-fg); border-radius: 0 0 8px 8px; font-weight: 600; font-size: 0.875rem; text-decoration: none; }
    .skip-link:focus { top: 0; }
    /* Mobile touch targets: btn-sm grows to 44px on touch devices */
    @media (pointer: coarse) {
      .btn-sm { min-height: 44px; min-width: 44px; padding: 10px 14px; }
      .filter-toggle-btn { min-height: 36px; padding: 6px 10px; }
    }
    /* Responsive: table overflow on narrow screens */
    @media (max-width: 600px) {
      .sessions-table, .hosts-table, .gtable { overflow-x: auto; }
      .modal-box { padding: 18px 14px; max-width: calc(100vw - 24px); }
    }
    /* Pending approval bar — fixed top strip */
    .pending-bar {
      position: fixed; top: 0; left: 0; right: 0; z-index: 200;
      min-height: 44px; display: flex; align-items: center; gap: 12px;
      padding: 0 20px; background: var(--warning-bg);
      border-bottom: 1.5px solid var(--warning-border);
      font-size: 0.875rem;
    }
    .pbar-icon { color: var(--warning); font-size: 1.0625rem; flex-shrink: 0; line-height: 1; }
    .pbar-main { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); }
    .pbar-host { font-weight: 700; }
    .pbar-sep { color: var(--text-3); margin: 0 5px; }
    .pbar-code { font-family: monospace; font-size: 0.8125rem; color: var(--text-2); }
    .pbar-exp { font-size: 0.8125rem; color: var(--text-2); }
    .pbar-actions { display: flex; gap: 6px; flex-shrink: 0; align-items: center; }
    .pbar-actions form { display: contents; }
    /* Push sidebar + main down when bar is visible */
    .has-pending .sidebar { padding-top: 44px; }
    .has-pending .main { padding-top: 74px; } /* 30px base + 44px bar */
    @media (max-width: 768px) {
      body.has-pending { padding-top: 44px; }
    }
    /* Pending approvals modal */
    .pending-modal-box { width: max-content; min-width: 680px; max-width: min(1200px, 95vw); }
    .pending-table { display: grid; grid-template-columns: auto auto auto auto auto; column-gap: 12px; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 16px; }
    .pending-table--admin { grid-template-columns: auto auto auto auto auto auto; }
    .pending-table-header { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .pending-table-row { display: grid; grid-column: 1/-1; grid-template-columns: subgrid; border-bottom: 1px solid var(--border); align-items: center; }
    .pending-table-footer { display: grid; grid-template-columns: auto auto auto auto auto; column-gap: 12px; padding: 10px 12px; align-items: center; }
    .pending-table-footer.pending-table--admin { grid-template-columns: auto auto auto auto auto auto; }
    .pending-table-header > .gtcol { padding: 8px 6px; white-space: nowrap; }
    .pending-table-header > .gtcol:first-child { padding-left: 12px; }
    .pending-table-header > .gtcol:last-child { padding-right: 12px; }
    .pending-table-row > .gtcol { padding: 10px 6px; }
    .pending-table-row > .gtcol:first-child { padding-left: 12px; }
    .pending-table-row > .gtcol:last-child { padding-right: 12px; }
    .row-code { white-space: nowrap; }
    .pending-table-row:last-child { border-bottom: none; }
    .pending-table-row:hover { background: var(--surface-2); }
    .pending-table-actions { display: flex; gap: 6px; align-items: center; flex-shrink: 0; }
    .pending-table-actions form { display: contents; }
    .pending-table-actions .btn { flex: 1; text-align: center; }
    /* Justification choice picker */
    .just-pick { display: inline-flex; align-items: center; gap: 4px; flex-wrap: nowrap; }
    .just-sel { font-size: 0.75rem; padding: 3px 6px; border: 1px solid var(--border); border-radius: 5px; background: var(--surface); color: var(--text); cursor: pointer; }
    .just-custom { font-size: 0.75rem; padding: 3px 7px; border: 1px solid var(--border); border-radius: 5px; background: var(--surface); color: var(--text); width: 130px; }
    .just-err { color: var(--danger, #c0392b); font-size: 0.75rem; display: block; margin-top: 2px; }
`

// pendingBarHTML is the pending-approval notification bar embedded in every
// app-layout template. It renders a slim fixed banner when the user has
// pending sudo challenges: inline approve/reject for a single challenge,
// or a "Review" button opening a modal table for multiple.
const pendingBarHTML = `{{if .Pending}}
<div class="pending-bar" aria-live="polite" aria-atomic="false">
  <span class="pbar-icon">&#x26A0;</span>
  {{if eq (len .Pending) 1}}{{with index .Pending 0}}
  <span class="pbar-main">
    {{if $.IsAdmin}}<strong class="pbar-host">{{.Username}}</strong><span class="pbar-sep">@</span>{{end}}<strong class="pbar-host">{{.Hostname}}</strong><span class="pbar-sep">·</span><span class="pbar-code">{{.Code}}</span><span class="pbar-sep">·</span><span class="pbar-exp">{{call $.T "expires_in"}} {{.ExpiresIn}}</span>{{if .Reason}}<span class="pbar-sep">·</span><span class="challenge-reason" style="font-size:0.8125rem;color:var(--text-2);font-style:italic">"{{.Reason}}"</span>{{end}}
  </span>
  <div class="pbar-actions">
    {{if or (not .AdminRequired) $.IsAdmin}}
    <form method="POST" action="/api/challenges/approve" style="display:flex;align-items:center;gap:4px" data-has-just="1">
      <input type="hidden" name="challenge_id" value="{{.ID}}">
      <input type="hidden" name="username" value="{{$.Username}}">
      <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
      <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
      <input type="hidden" name="from" value="inline">
      {{if .Reason}}
      <input type="hidden" name="reason" value="{{.Reason}}">
      {{else}}
      <span class="just-pick" data-required="{{if $.RequireJustification}}true{{else}}false{{end}}">
        <select class="just-sel">
          {{if not $.RequireJustification}}<option value="">{{call $.T "reason_optional"}}</option>{{end}}
          {{range $.JustificationChoices}}<option value="{{.}}">{{.}}</option>{{end}}
          <option value="__custom__">{{call $.T "custom_reason"}}</option>
        </select>
        <input type="text" class="just-custom" maxlength="500" placeholder="{{call $.T "enter_reason"}}" style="display:none">
        <input type="hidden" class="just-val" name="reason" value="">
      </span>
      {{end}}
      <button type="submit" class="btn btn-success btn-sm">{{call $.T "approve"}}</button>
    </form>
    {{end}}
    <form method="POST" action="/api/challenges/reject">
      <input type="hidden" name="challenge_id" value="{{.ID}}">
      <input type="hidden" name="username" value="{{$.Username}}">
      <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
      <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
      <button type="submit" class="btn btn-danger btn-sm saction-confirm" data-confirm="{{call $.T "confirm_reject_all"}}">{{call $.T "reject"}}</button>
    </form>
  </div>
  {{end}}{{else}}
  <span class="pbar-main"><strong>{{len .Pending}}</strong> {{call .T "pending_requests"}}</span>
  <div class="pbar-actions">
    <button type="button" class="btn btn-sm btn-primary" id="pending-modal-open-btn">{{call .T "view"}} &rsaquo;</button>
  </div>
  {{end}}
</div>
{{if gt (len .Pending) 1}}
<div class="modal-overlay" id="pending-modal" role="dialog" aria-modal="true" aria-labelledby="pending-modal-title">
  <div class="modal-box pending-modal-box">
    <h3 id="pending-modal-title">{{call .T "pending_requests"}}</h3>
    <div class="pending-table{{if .IsAdmin}} pending-table--admin{{end}}" role="table" aria-label="{{call .T "pending_requests"}}">
      <div class="pending-table-header" role="row">
        {{if .IsAdmin}}<div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "user"}}</span></div>{{end}}
        <div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "host"}}</span></div>
        <div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "code"}}</span></div>
        <div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "time_remaining"}}</span></div>
        <div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "reason"}}</span></div>
        <div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "action"}}</span></div>
      </div>
      {{range .Pending}}
      <div class="pending-table-row" role="row">
        {{if $.IsAdmin}}<div class="gtcol" role="cell"><span class="pill user">{{.Username}}</span></div>{{end}}
        <div class="gtcol" role="cell"><div style="display:flex;flex-direction:column;min-width:0;overflow:hidden;flex:1"><span class="row-host" style="font-size:0.875rem">{{.Hostname}}</span>{{if .AdminRequired}}&nbsp;<span class="admin-req">&#x1F512; {{call $.T "admin_approval_required"}}</span>{{end}}</div></div>
        <div class="gtcol" role="cell"><span class="row-code" style="display:inline">{{.Code}}</span></div>
        <div class="gtcol" role="cell"><span style="font-size:0.8125rem;color:var(--text-2)">{{.ExpiresIn}}</span></div>
        <div class="gtcol" role="cell">
          {{if or (not .AdminRequired) $.IsAdmin}}
          {{if .Reason}}
          <span class="just-pick" data-required="false">
            <input type="hidden" class="just-val" value="{{.Reason}}">
            <span style="font-size:0.8125rem;color:var(--text-2);font-style:italic">"{{.Reason}}"</span>
          </span>
          {{else}}
          <span class="just-pick" data-required="{{if $.RequireJustification}}true{{else}}false{{end}}">
            <select class="just-sel">
              {{if not $.RequireJustification}}<option value="">{{call $.T "reason_optional"}}</option>{{end}}
              {{range $.JustificationChoices}}<option value="{{.}}">{{.}}</option>{{end}}
              <option value="__custom__">{{call $.T "custom_reason"}}</option>
            </select>
            <input type="text" class="just-custom" maxlength="500" placeholder="{{call $.T "enter_reason"}}" style="display:none">
            <input type="hidden" class="just-val" value="">
          </span>
          {{end}}
          {{end}}
        </div>
        <div class="gtcol pending-table-actions" role="cell">
          {{if or (not .AdminRequired) $.IsAdmin}}
          <button type="button" class="btn btn-success btn-sm pending-row-approve" data-id="{{.ID}}" data-username="{{$.Username}}" data-csrf="{{$.CSRFToken}}" data-csrf-ts="{{$.CSRFTs}}">{{call $.T "approve"}}</button>
          {{end}}
          <button type="button" class="btn btn-danger btn-sm pending-row-reject" data-id="{{.ID}}" data-username="{{$.Username}}" data-csrf="{{$.CSRFToken}}" data-csrf-ts="{{$.CSRFTs}}">{{call $.T "reject"}}</button>
        </div>
      </div>
      {{end}}
    </div>
    <div class="pending-table-footer" style="border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:6px;padding:12px 12px 10px">
      <div class="pending-table-actions" style="flex:none">
        <form method="POST" action="/api/challenges/approve-all" style="display:inline">
          <input type="hidden" name="username" value="{{.Username}}">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
          <button type="submit" class="btn btn-success btn-sm saction-confirm" data-confirm="{{call .T "confirm_approve_all"}}">{{call .T "approve_all"}}</button>
        </form>
        <form method="POST" action="/api/challenges/reject-all" style="display:inline">
          <input type="hidden" name="username" value="{{.Username}}">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
          <button type="submit" class="btn btn-danger btn-sm saction-confirm" data-confirm="{{call .T "confirm_reject_all"}}">{{call .T "reject_all"}}</button>
        </form>
      </div>
    </div>
  </div>
</div>
<script nonce="{{.CSPNonce}}">
var _pendingModalPrevFocus=null;
function openPendingModal(){
  _pendingModalPrevFocus=document.activeElement;
  var m=document.getElementById('pending-modal');
  if(m){
    m.classList.add('open');
    var focusable=Array.from(m.querySelectorAll('button,input,select,textarea,[tabindex="0"]')).filter(function(el){return !el.disabled&&el.offsetParent!==null;});
    if(focusable.length)setTimeout(function(){focusable[0].focus();},50);
  }
}
function closePendingModal(){
  var m=document.getElementById('pending-modal');
  if(m)m.classList.remove('open');
  if(_pendingModalPrevFocus)_pendingModalPrevFocus.focus();
}
(function(){
  var openBtn=document.getElementById('pending-modal-open-btn');
  if(openBtn)openBtn.addEventListener('click',openPendingModal);
  var overlay=document.getElementById('pending-modal');
  if(overlay)overlay.addEventListener('click',function(e){if(e.target===overlay)closePendingModal();});
})();
document.addEventListener('keydown',function(e){if(e.key==='Escape'){var m=document.getElementById('pending-modal');if(m&&m.classList.contains('open'))closePendingModal();}});
// Wire confirmation dialogs for ALL saction-confirm buttons (including single-challenge reject).
document.querySelectorAll('.saction-confirm').forEach(function(btn){
  btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});
});
// Justification picker: sync hidden value on select change, reveal custom input.
(function(){
  function initPicker(pick){
    var sel=pick.querySelector('.just-sel');
    var custom=pick.querySelector('.just-custom');
    var hidden=pick.querySelector('.just-val');
    if(!sel)return;
    function sync(){
      if(sel.value==='__custom__'){
        if(custom)custom.style.display='';
        if(hidden)hidden.value=custom?custom.value.trim():'';
      }else{
        if(custom)custom.style.display='none';
        if(hidden)hidden.value=sel.value;
      }
    }
    sel.addEventListener('change',sync);
    if(custom)custom.addEventListener('input',function(){if(hidden&&sel.value==='__custom__')hidden.value=custom.value.trim();});
    sync();
  }
  document.querySelectorAll('.just-pick').forEach(initPicker);
  // Re-init pickers inside the modal on modal open (pickers are always present in DOM)
  var origOpen=window.openPendingModal;
  if(origOpen)window.openPendingModal=function(){origOpen();document.querySelectorAll('#pending-modal .just-pick').forEach(initPicker);};
})();
// Validate justification on form submit for forms with data-has-just attribute.
document.querySelectorAll('form[data-has-just]').forEach(function(form){
  form.addEventListener('submit',function(e){
    var pick=form.querySelector('.just-pick');
    if(!pick)return;
    var sel=pick.querySelector('.just-sel');
    var custom=pick.querySelector('.just-custom');
    var hidden=pick.querySelector('.just-val');
    var val=sel&&sel.value==='__custom__'?(custom?custom.value.trim():''):(sel?sel.value:'');
    if(hidden)hidden.value=val;
    if(pick.dataset.required==='true'&&!val){
      e.preventDefault();
      var err=pick.querySelector('.just-err');
      if(!err){err=document.createElement('span');err.className='just-err';pick.appendChild(err);}
      err.textContent='Please select a justification.';
    }
  });
});
// Per-row approve/reject in modal: fetch, remove row, close modal if empty.
document.querySelectorAll('.pending-row-approve,.pending-row-reject').forEach(function(btn){
  btn.addEventListener('click',function(){
    var row=btn.closest('.pending-table-row');
    var action=btn.classList.contains('pending-row-approve')?'approve':'reject';
    var pick=row&&row.querySelector('.just-pick');
    var reason='';
    if(pick){
      var sel=pick.querySelector('.just-sel');
      var custom=pick.querySelector('.just-custom');
      var hidden=pick.querySelector('.just-val');
      reason=hidden?hidden.value:(sel&&sel.value!=='__custom__'?sel.value:(custom?custom.value.trim():''));
    }
    if(pick&&pick.dataset.required==='true'&&!reason&&action==='approve'){
      var err=pick.querySelector('.just-err');
      if(!err){err=document.createElement('span');err.className='just-err';pick.appendChild(err);}
      err.textContent='Please select a justification.';
      return;
    }
    var body='challenge_id='+encodeURIComponent(btn.dataset.id)
      +'&username='+encodeURIComponent(btn.dataset.username)
      +'&csrf_token='+encodeURIComponent(btn.dataset.csrf)
      +'&csrf_ts='+encodeURIComponent(btn.dataset.csrfTs)
      +(reason?'&reason='+encodeURIComponent(reason):'');
    fetch('/api/challenges/'+action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(){
        if(row)row.remove();
        var remaining=document.querySelectorAll('#pending-modal .pending-table-row');
        if(!remaining.length)closePendingModal();
      });
  });
});
(function(){
  var pm=document.getElementById('pending-modal');
  if(pm){
    pm.addEventListener('keydown',function(e){
      if(e.key!=='Tab')return;
      var focusable=Array.from(pm.querySelectorAll('button,input,select,textarea,[tabindex="0"]')).filter(function(el){return !el.disabled&&el.offsetParent!==null;});
      if(!focusable.length){e.preventDefault();return;}
      var first=focusable[0],last=focusable[focusable.length-1];
      if(e.shiftKey){if(document.activeElement===first){e.preventDefault();last.focus();}}
      else{if(document.activeElement===last){e.preventDefault();first.focus();}}
    });
  }
})();
</script>
{{end}}
{{end}}`

// formatTime formats a time as "2006-01-02 15:04 UTC".
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}


// timeAgoI18n formats a time as a localized human-readable relative string.
func timeAgoI18n(when time.Time, t func(string) string) string {
	d := time.Since(when)
	if d < time.Minute {
		return t("just_now")
	}
	return formatDuration(t, d) + " " + t("ago")
}

// historyViewEntry is a pre-formatted history entry for the template.
type historyViewEntry struct {
	Action        string
	ActionLabel   string
	Hostname      string
	Code          string
	Actor         string
	Username      string
	FormattedTime string
	TimeAgo       string
	Reason        string
}

// timelineEntry represents one hour-slot in the 24-hour activity timeline.
type timelineEntry struct {
	Hour         int
	HourLabel    string // "14:00"
	Count        int
	Height       int // bar height in pixels (2-40)
	IsNow        bool
	HoursAgo     int    // offset from now (0 = current hour)
	Details      string // rich tooltip text
	HourStartISO string // "2006-01-02T15:04" for datetime-local input
	HourEndISO   string // "2006-01-02T15:04" for datetime-local input
}

// ActionOption represents a value/label pair for dropdown select options.
type ActionOption struct {
	Value string
	Label string
}


// navCSS is appended to sharedCSS in app-layout pages (no extra styles needed now).
const navCSS = ``

// sidebarNavHTML is the shared sidebar nav items for all full-page templates.
// It uses Go template variables: .ActivePage, .IsAdmin, .AdminTab.
// The caller must embed this inside <nav class="sidebar"><div class="sidebar-nav">...</div></nav>.
const sidebarNavHTML = `
      <a href="/" class="nav-item{{if eq .ActivePage "sessions"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>{{call .T "sessions"}}{{if .Pending}}<span class="nav-badge">{{len .Pending}}</span>{{end}}</a>
      <a href="/access" class="nav-item{{if eq .ActivePage "access"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>{{call .T "access"}}</a>
      <a href="/history" class="nav-item{{if eq .ActivePage "history"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call .T "history"}}</a>
      {{if .IsAdmin}}<a href="/admin" class="nav-item{{if eq .ActivePage "admin"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>{{call .T "admin"}}</a>
      <div class="sidebar-sub">
        <a href="/admin/users" class="sub-item{{if eq .AdminTab "users"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>{{call .T "users"}}</a>
        <a href="/admin/groups" class="sub-item{{if eq .AdminTab "groups"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>{{call .T "groups"}}</a>
        <a href="/admin/hosts" class="sub-item{{if eq .AdminTab "hosts"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>{{call .T "hosts"}}</a>
        {{if .BridgeMode}}<a href="/admin/sudo-rules" class="sub-item{{if eq .AdminTab "sudo-rules"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>{{call .T "sudo_rules"}}</a>{{end}}
        <a href="/admin/notifications" class="sub-item{{if eq .AdminTab "notifications"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>{{call .T "notify_tab"}}</a>
        <a href="/admin/config" class="sub-item{{if eq .AdminTab "config"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>{{call .T "config"}}</a>
        <a href="/admin/info" class="sub-item{{if eq .AdminTab "info"}} active{{end}}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>{{call .T "info"}}</a>
      </div>{{end}}`

// tzOptionsHTML is the timezone <option> list reused in the profile dropdown across all pages.
const tzOptionsHTML = `
    <option value="UTC" {{if eq .Timezone "UTC"}}selected{{end}}>UTC</option>
    <optgroup label="Americas">
      <option value="Pacific/Honolulu" {{if eq .Timezone "Pacific/Honolulu"}}selected{{end}}>UTC-10 (Hawaii)</option>
      <option value="America/Anchorage" {{if eq .Timezone "America/Anchorage"}}selected{{end}}>UTC-9 (Alaska)</option>
      <option value="America/Los_Angeles" {{if eq .Timezone "America/Los_Angeles"}}selected{{end}}>UTC-8 (Los Angeles, Vancouver)</option>
      <option value="America/Denver" {{if eq .Timezone "America/Denver"}}selected{{end}}>UTC-7 (Denver, Phoenix)</option>
      <option value="America/Chicago" {{if eq .Timezone "America/Chicago"}}selected{{end}}>UTC-6 (Chicago, Mexico City)</option>
      <option value="America/New_York" {{if eq .Timezone "America/New_York"}}selected{{end}}>UTC-5 (New York, Toronto)</option>
      <option value="America/Halifax" {{if eq .Timezone "America/Halifax"}}selected{{end}}>UTC-4 (Halifax, Bermuda)</option>
      <option value="America/St_Johns" {{if eq .Timezone "America/St_Johns"}}selected{{end}}>UTC-3:30 (Newfoundland)</option>
      <option value="America/Sao_Paulo" {{if eq .Timezone "America/Sao_Paulo"}}selected{{end}}>UTC-3 (São Paulo, Buenos Aires)</option>
    </optgroup>
    <optgroup label="Europe &amp; Africa">
      <option value="Atlantic/Reykjavik" {{if eq .Timezone "Atlantic/Reykjavik"}}selected{{end}}>UTC+0 (Reykjavik)</option>
      <option value="Europe/London" {{if eq .Timezone "Europe/London"}}selected{{end}}>UTC+0 (London, Dublin)</option>
      <option value="Europe/Paris" {{if eq .Timezone "Europe/Paris"}}selected{{end}}>UTC+1 (Paris, Berlin, Amsterdam)</option>
      <option value="Europe/Helsinki" {{if eq .Timezone "Europe/Helsinki"}}selected{{end}}>UTC+2 (Helsinki, Cairo, Johannesburg)</option>
      <option value="Europe/Moscow" {{if eq .Timezone "Europe/Moscow"}}selected{{end}}>UTC+3 (Moscow, Istanbul, Nairobi)</option>
    </optgroup>
    <optgroup label="Asia &amp; Pacific">
      <option value="Asia/Dubai" {{if eq .Timezone "Asia/Dubai"}}selected{{end}}>UTC+4 (Dubai, Baku)</option>
      <option value="Asia/Kolkata" {{if eq .Timezone "Asia/Kolkata"}}selected{{end}}>UTC+5:30 (Mumbai, New Delhi)</option>
      <option value="Asia/Dhaka" {{if eq .Timezone "Asia/Dhaka"}}selected{{end}}>UTC+6 (Dhaka, Almaty)</option>
      <option value="Asia/Bangkok" {{if eq .Timezone "Asia/Bangkok"}}selected{{end}}>UTC+7 (Bangkok, Jakarta)</option>
      <option value="Asia/Shanghai" {{if eq .Timezone "Asia/Shanghai"}}selected{{end}}>UTC+8 (Shanghai, Singapore, Perth)</option>
      <option value="Asia/Tokyo" {{if eq .Timezone "Asia/Tokyo"}}selected{{end}}>UTC+9 (Tokyo, Seoul)</option>
      <option value="Australia/Sydney" {{if eq .Timezone "Australia/Sydney"}}selected{{end}}>UTC+10 (Sydney, Melbourne)</option>
      <option value="Pacific/Auckland" {{if eq .Timezone "Pacific/Auckland"}}selected{{end}}>UTC+12 (Auckland, Fiji)</option>
    </optgroup>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{call .T "sessions"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 28 28' fill='none'%3E%3Ccircle cx='14' cy='5' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='8.5' x2='14' y2='13' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='7' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='21' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='7' cy='21' r='3.5' fill='%23a855f7'/%3E%3Ccircle cx='21' cy='21' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='13' x2='14' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='14' cy='21' r='3.5' fill='%23a855f7'/%3E%3C/svg%3E">
  <style>` + sharedCSS + navCSS + `
    .host-access-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
    .history-entry { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 7px; margin: 0 -12px; }
    .history-entry:hover { background: var(--surface-2); }
    .history-time { font-size: 0.75rem; color: var(--text-2); white-space: nowrap; flex-shrink: 0; min-width: 52px; }
    .history-host { color: var(--text); font-size: 0.8125rem; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .history-actor { font-size: 0.75rem; color: var(--text-2); white-space: nowrap; flex-shrink: 0; }
    .view-all { display: block; margin-top: 10px; font-size: 0.8125rem; color: var(--primary); text-decoration: none; font-weight: 600; }
    .view-all:hover { text-decoration: underline; }
    .sessions-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
    .sessions-table { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .sessions-table-header { display: grid; grid-template-columns: 200px 1.8fr 1.2fr 210px; gap: 0; padding: 8px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .sessions-table-filter { display: grid; grid-template-columns: 200px 1.8fr 1.2fr 210px; gap: 0; padding: 5px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .sessions-table-header .gtcol { align-items: center; }
    .sessions-table-row { display: grid; grid-template-columns: 200px 1.8fr 1.2fr 210px; gap: 0; padding: 10px 12px; border-bottom: 1px solid var(--border); align-items: center; }
    .sessions-table--user .sessions-table-header,
    .sessions-table--user .sessions-table-filter,
    .sessions-table--user .sessions-table-row { grid-template-columns: 200px 1.5fr 210px; }
    .sessions-table-row:last-child { border-bottom: none; }
    .sessions-table-row:hover { background: var(--surface-2); }
    @keyframes session-pulse { 0% { background: rgba(34,197,94,0.18); } 100% { background: transparent; } }
    .session-highlight { animation: session-pulse 2s ease-out; }
    .saction-btn { display: inline-flex; align-items: center; gap: 5px; padding: 5px 11px; border-radius: 6px; font-size: 0.8125rem; font-weight: 500; border: 1px solid var(--border); background: var(--surface); color: var(--text-2); cursor: pointer; transition: background 0.15s, color 0.15s, border-color 0.15s; line-height: 1.4; white-space: nowrap; }
    .saction-btn:hover { background: var(--surface-2); color: var(--text); border-color: var(--text-3); }
    .saction-btn.saction-danger { color: var(--danger); }
    .saction-btn.saction-danger:hover { background: rgba(220,53,69,0.08); border-color: var(--danger); }
    .saction-btn.saction-primary { color: var(--primary); }
    .saction-btn.saction-primary:hover { background: var(--primary-sub); border-color: rgba(124,58,237,0.4); }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    // Auto-dismiss success banners after 5 seconds
    document.querySelectorAll('.banner-success').forEach(function(el){
      setTimeout(function(){el.style.transition='opacity 0.4s';el.style.opacity='0';setTimeout(function(){el.style.display='none';},400);},5000);
    });
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    // User menu toggle
    document.querySelectorAll('.user-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var open=btn.classList.contains('open');
        document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});
        if(!open){btn.classList.add('open');btn.setAttribute('aria-expanded','true');}
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});});
    // Active-only filter toggle
    var filterBtn=document.getElementById('active-filter-btn');
    var hostList=document.getElementById('host-access-list');
    if(filterBtn&&hostList){
      var activeOnly=localStorage.getItem('pam_active_only')==='1';
      function applyFilter(){
        hostList.classList.toggle('active-only',activeOnly);
        filterBtn.classList.toggle('active',activeOnly);
        filterBtn.setAttribute('aria-checked',activeOnly);
      }
      applyFilter();
      filterBtn.addEventListener('click',function(){activeOnly=!activeOnly;localStorage.setItem('pam_active_only',activeOnly?'1':'0');applyFilter();});
      filterBtn.addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();activeOnly=!activeOnly;localStorage.setItem('pam_active_only',activeOnly?'1':'0');applyFilter();}});
    }
  });
  function connectSSE(url, onMessage, onError) {
    var delay = 1000;
    var es;
    function connect() {
      es = new EventSource(url);
      es.addEventListener('update', onMessage);
      es.onerror = function() {
        es.close();
        if (onError) onError(es);
        setTimeout(connect, delay);
        delay = Math.min(delay * 2, 30000);
      };
    }
    connect();
    return function() { if (es) es.close(); };
  }
  var _dashSSECleanup = connectSSE('/api/events', function(e) {
    if (e && e.data && e.data.indexOf('401') !== -1) { window.location.href = '/login'; return; }
    var pm=document.getElementById('pending-modal');
    if(pm&&pm.classList.contains('open'))return;
    location.reload();
  }, function(es) {
    // on repeated errors, check if session expired by a quick fetch
  });
  window.addEventListener('beforeunload', function() { _dashSSECleanup(); });
  document.querySelectorAll('.saction-btn[type=submit]').forEach(function(btn){
    btn.addEventListener('click',function(e){
      if(btn.dataset.confirm){if(!confirm(btn.dataset.confirm)){return;}}
      e.preventDefault();
      btn.disabled=true;
      btn.style.opacity='0.6';
      btn.closest('form').submit();
    });
  });
  </script>
</head>
<body class="app{{if .Pending}} has-pending{{end}}">
  <a href="#main-content" class="skip-link">{{call .T "skip_to_content"}}</a>` + pendingBarHTML + `
  <nav class="sidebar" aria-label="Main navigation">
    <div class="sidebar-brand">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 28 28" fill="none" aria-hidden="true"><circle cx="14" cy="5" r="3.5" fill="currentColor"/><line x1="14" y1="8.5" x2="14" y2="13" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="7" y2="18" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="21" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="21" r="3.5" fill="currentColor"/><circle cx="21" cy="21" r="3.5" fill="currentColor"/><line x1="14" y1="13" x2="14" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="14" cy="21" r="3.5" fill="currentColor"/></svg>
      {{call .T "app_name"}}
    </div>
    <div class="sidebar-nav">` + sidebarNavHTML + `
    </div>
    <div class="sidebar-footer">
      <div class="user-btn" tabindex="0" role="button" aria-label="{{call .T "aria_user_menu"}}" aria-haspopup="true" aria-expanded="false">
        <div class="user-avatar">{{if .Avatar}}<img src="{{.Avatar}}" alt="">{{else}}{{.Initial}}{{end}}</div>
        <div class="user-name-wrap"><span class="user-display-name">{{.Username}}{{if .IsAdmin}}<span class="user-role-badge">{{call .T "admin"}}</span>{{end}}</span></div>
        <div class="user-dropdown">
          <div class="user-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/"><select name="lang" class="lang-select" aria-label="{{call .T "language"}}">{{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/"><select name="tz" class="tz-select" aria-label="{{call .T "timezone"}}">` + tzOptionsHTML + `</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-opts">
            <a href="/theme?set=system&from=/" class="theme-opt{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/" class="theme-opt{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/" class="theme-opt{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="user-dropdown-divider"></div>
          <form method="POST" action="/signout" style="display:inline;margin:0"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="csrf_ts" value="{{.CSRFTs}}"><button type="submit" class="user-dropdown-item" style="width:100%;text-align:left;background:none;border:none;cursor:pointer;color:var(--danger);font:inherit;font-size:0.8125rem;font-weight:500;padding:7px 14px">{{call .T "sign_out"}}</button></form>
        </div>
      </div>
    </div>
  </nav>
  <main class="main" id="main-content">
    <h1 class="sr-only">{{call .T "sessions"}} - {{call .T "app_name"}}</h1>
    {{if .PocketIDUnavailable}}<div class="banner banner-warning">{{call .T "pocketid_unavailable"}}</div>{{end}}
    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}


    {{if .IsAdmin}}
    <div class="sessions-table" id="sessions-table" data-prefilter-user="{{.FilterUser}}" data-prefilter-host="{{.FilterHost}}" role="table" aria-label="{{call .T "sessions"}}">
      <div class="sessions-table-header" role="row">
        <div class="gtcol gtcol-suser" role="columnheader" style="gap:10px;align-items:center;flex-wrap:wrap">
          <button type="button" class="filter-toggle-btn" id="sessions-admin-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button>
          <span class="col-sort-link">{{call .T "user"}}</span>
          <div class="toggle-wrap" id="just-mine-toggle" role="switch" aria-checked="false" tabindex="0" data-username="{{.Username}}"><span>{{call .T "just_me"}}</span><div class="toggle-track"><div class="toggle-thumb"></div></div></div>
        </div>
        <div class="gtcol gtcol-shost" role="columnheader"><span class="col-sort-link">{{call .T "host"}}</span></div>
        <div class="gtcol gtcol-sremaining" role="columnheader"><span class="col-sort-link">{{call .T "time_remaining"}}</span></div>
        <div class="gtcol gtcol-sactions" role="columnheader"><span class="col-sort-link">{{call .T "action"}}</span></div>
      </div>
      <div class="sessions-table-filter" id="sessions-admin-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="suser" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="shost" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="sremaining" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div style="display:flex;justify-content:flex-end;align-items:center;padding:0 6px"><button type="button" class="filter-clear-btn" id="sessions-admin-clear">{{call .T "clear_filter"}}</button></div>
      </div>
      {{range .AllSessions}}
      <div class="sessions-table-row{{if and $.HighlightUser (eq .Username $.HighlightUser) (eq .Hostname $.HighlightHost)}} session-highlight{{end}}" role="row" data-user="{{.Username}}" data-host="{{.Hostname}}">
        <div class="gtcol gtcol-suser" role="cell"><a href="/access?user={{.Username}}" class="pill user">{{.Username}}</a></div>
        <div class="gtcol gtcol-shost" role="cell"><a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a></div>
        <div class="gtcol gtcol-sremaining" role="cell"><span class="row-sub" style="font-size:0.8125rem">{{.Remaining}}</span></div>
        <div class="gtcol gtcol-sactions" role="cell" style="gap:6px;flex-wrap:nowrap;align-items:center;">
          <div class="elevate-wrap">
            <button type="button" class="saction-btn saction-primary elevate-toggle"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call $.T "extend"}}<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px"><polyline points="6 9 12 15 18 9"/></svg></button>
            <form method="POST" action="/api/sessions/extend" class="elevate-menu">
              <input type="hidden" name="hostname" value="{{.Hostname}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="session_username" value="{{.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <input type="hidden" name="from" value="/">
              {{range .ExtendDurations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
              <button type="submit" name="duration" value="max">{{call $.T "max"}}</button>
            </form>
          </div>
          <form method="POST" action="/api/sessions/revoke" style="display:inline">
            <input type="hidden" name="hostname" value="{{.Hostname}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="session_username" value="{{.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <input type="hidden" name="from" value="/">
            <button type="submit" class="saction-btn saction-danger saction-confirm" data-confirm="{{printf (call $.T "confirm_revoke_session_user") .Username .Hostname}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>{{call $.T "revoke"}}</button>
          </form>
        </div>
      </div>
      {{end}}
      {{if not .AllSessions}}
      <div style="text-align:center;color:var(--text-2);font-size:0.875rem;padding:20px 0">{{call .T "no_sudo_session"}}</div>
      {{end}}
    </div>
    <div class="pagination-bar" id="sessions-admin-pagination"></div>
    {{if .AllSessions}}
    <div style="display:flex;justify-content:flex-end;margin-top:8px">
      <form method="POST" action="/api/sessions/revoke-all">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <input type="hidden" name="from" value="/">
        <button type="submit" class="saction-btn saction-danger saction-confirm" data-confirm="{{call .T "confirm_revoke_all"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>{{call .T "revoke_all"}}</button>
      </form>
    </div>
    {{end}}
    <script nonce="{{.CSPNonce}}">
    (function(){
      var justMineActive=false,myUsername='';
      var sessionsAdminPage=1,sessionsAdminPs={{.DefaultPageSize}};
      function renderSessionsAdminPager(vis){
        var bar=document.getElementById('sessions-admin-pagination');
        if(!bar)return;
        var total=vis.length,totalPages=Math.max(1,Math.ceil(total/sessionsAdminPs));
        if(sessionsAdminPage>totalPages)sessionsAdminPage=1;
        var start=(sessionsAdminPage-1)*sessionsAdminPs;
        var allRows=Array.from(document.querySelectorAll('#sessions-table .sessions-table-row'));
        allRows.forEach(function(r){r.style.display='none';});
        vis.slice(start,start+sessionsAdminPs).forEach(function(r){r.style.display='';});
        if(totalPages<=1&&total>0){bar.innerHTML='';vis.forEach(function(r){r.style.display='';});return;}
        if(total===0){bar.innerHTML='';return;}
        bar.innerHTML='<button class="pagination-btn" '+(sessionsAdminPage<=1?'disabled':'')+'>&#8592;</button><span class="pagination-info">'+(start+1)+'&#8211;'+Math.min(start+sessionsAdminPs,total)+' of '+total+'</span><button class="pagination-btn" '+(sessionsAdminPage>=totalPages?'disabled':'')+'>&#8594;</button><select class="pagination-size-select">'+[15,30,50,100].map(function(n){return'<option value="'+n+'"'+(n===sessionsAdminPs?' selected':'')+'>'+n+' per page</option>';}).join('')+'</select>';
        var btns=bar.querySelectorAll('.pagination-btn');
        if(!btns[0].disabled)btns[0].addEventListener('click',function(){sessionsAdminPage--;filterSessions();});
        if(!btns[1].disabled)btns[1].addEventListener('click',function(){sessionsAdminPage++;filterSessions();});
        bar.querySelector('.pagination-size-select').addEventListener('change',function(){sessionsAdminPs=parseInt(this.value);sessionsAdminPage=1;filterSessions();});
      }
      function filterSessions(){
        var filters={};
        document.querySelectorAll('#sessions-table .gtcol-filter-input').forEach(function(inp){ filters[inp.dataset.col]=inp.value.toLowerCase().trim(); });
        var allRows=Array.from(document.querySelectorAll('#sessions-table .sessions-table-row'));
        var vis=allRows.filter(function(row){
          for(var col in filters){ if(!filters[col]) continue; var cell=row.querySelector('.gtcol-'+col); if(cell&&cell.textContent.toLowerCase().indexOf(filters[col])===-1){return false;} }
          if(justMineActive&&myUsername){var uc=row.querySelector('.gtcol-suser');if(uc&&uc.textContent.trim().toLowerCase()!==myUsername.toLowerCase()){return false;}}
          return true;
        });
        renderSessionsAdminPager(vis);
      }
      document.querySelectorAll('#sessions-table .gtcol-filter-input').forEach(function(inp){ inp.addEventListener('input',filterSessions); });
      var tbl=document.getElementById('sessions-table');
      if(tbl){
        var pfu=tbl.dataset.prefilterUser,pfh=tbl.dataset.prefilterHost;
        if(pfu){var inp=tbl.querySelector('.gtcol-filter-input[data-col="suser"]');if(inp){inp.value=pfu;}}
        if(pfh){var inp2=tbl.querySelector('.gtcol-filter-input[data-col="shost"]');if(inp2){inp2.value=pfh;}}
        if(pfu||pfh){filterSessions();var sfr=document.getElementById('sessions-admin-filter-row');var sft=document.getElementById('sessions-admin-filter-toggle');if(sfr){sfr.style.display='';if(sft)sft.classList.add('active');}}
      }
      var jmt=document.getElementById('just-mine-toggle');
      if(jmt){
        myUsername=jmt.dataset.username||'';
        function toggleJM(){justMineActive=!justMineActive;jmt.classList.toggle('active',justMineActive);jmt.setAttribute('aria-checked',justMineActive?'true':'false');filterSessions();}
        jmt.addEventListener('click',toggleJM);
        jmt.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleJM();}});
      }
      document.querySelectorAll('.saction-confirm').forEach(function(btn){
        btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});
      });
      var sac=document.getElementById('sessions-admin-clear');
      if(sac)sac.addEventListener('click',function(){document.querySelectorAll('#sessions-table .gtcol-filter-input').forEach(function(i){i.value='';});filterSessions();});
      (function(){var ftb=document.getElementById('sessions-admin-filter-toggle');var ftr=document.getElementById('sessions-admin-filter-row');if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      document.querySelectorAll('.elevate-toggle').forEach(function(btn){
        btn.addEventListener('click',function(e){e.stopPropagation();var m=btn.parentElement.querySelector('.elevate-menu');var open=m.classList.contains('open');document.querySelectorAll('.elevate-menu.open').forEach(function(x){x.classList.remove('open');});if(!open){var r=btn.getBoundingClientRect();m.style.top=(r.bottom+4)+'px';m.style.right=(window.innerWidth-r.right)+'px';m.style.left='auto';m.classList.add('open');}});
      });
      document.addEventListener('click',function(){document.querySelectorAll('.elevate-menu.open').forEach(function(m){m.classList.remove('open');});});
      filterSessions();
    })();
    </script>
    {{else}}
    <div class="sessions-table sessions-table--user" id="user-sessions-table" role="table" aria-label="{{call .T "sessions"}}">
      <div class="sessions-table-header" role="row">
        <div class="gtcol gtcol-shost" role="columnheader" style="gap:8px;align-items:center">
          <button type="button" class="filter-toggle-btn" id="user-sessions-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button>
          <span class="col-sort-link">{{call .T "host"}}</span>
        </div>
        <div class="gtcol gtcol-sremaining" role="columnheader"><span class="col-sort-link">{{call .T "time_remaining"}}</span></div>
        <div class="gtcol gtcol-sactions" role="columnheader"><span class="col-sort-link">{{call .T "action"}}</span></div>
      </div>
      <div class="sessions-table-filter" id="user-sessions-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="shost" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div></div>
        <div></div>
      </div>
      {{range .HostAccess}}{{if .Active}}
      <div class="sessions-table-row{{if and $.HighlightHost (eq .Hostname $.HighlightHost)}} session-highlight{{end}}" role="row" data-host="{{.Hostname}}">
        <div class="gtcol gtcol-shost" role="cell"><a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a></div>
        <div class="gtcol gtcol-sremaining" role="cell"><span class="row-sub" style="font-size:0.8125rem">{{.Remaining}}</span></div>
        <div class="gtcol gtcol-sactions" role="cell" style="gap:6px;flex-wrap:nowrap;align-items:center;">
          <div class="elevate-wrap">
            <button type="button" class="saction-btn saction-primary elevate-toggle"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call $.T "extend"}}<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px"><polyline points="6 9 12 15 18 9"/></svg></button>
            <form method="POST" action="/api/sessions/extend" class="elevate-menu">
              <input type="hidden" name="hostname" value="{{.Hostname}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              {{range .ExtendDurations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
              <button type="submit" name="duration" value="max">{{call $.T "max"}}</button>
            </form>
          </div>
          <form method="POST" action="/api/sessions/revoke" style="display:inline">
            <input type="hidden" name="hostname" value="{{.Hostname}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="saction-btn saction-danger saction-confirm" data-confirm="{{printf (call $.T "confirm_revoke_session") .Hostname}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>{{call $.T "revoke"}}</button>
          </form>
        </div>
      </div>
      {{end}}{{end}}
      {{if not .HasActiveSessions}}
      <div style="text-align:center;color:var(--text-2);font-size:0.875rem;padding:20px 0">{{call .T "no_sudo_session"}}</div>
      {{end}}
    </div>
    <div class="pagination-bar" id="sessions-user-pagination"></div>
    {{if .HasActiveSessions}}
    <div style="display:flex;justify-content:flex-end;gap:6px;margin-top:8px">
      <form method="POST" action="/api/sessions/extend-all">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="saction-btn saction-primary saction-confirm" data-confirm="{{call .T "confirm_extend_all"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call .T "extend_all"}}</button>
      </form>
      <form method="POST" action="/api/sessions/revoke-all">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="saction-btn saction-danger saction-confirm" data-confirm="{{call .T "confirm_revoke_all"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>{{call .T "revoke_all"}}</button>
      </form>
    </div>
    {{end}}
    <script nonce="{{.CSPNonce}}">
    (function(){
      var activeOnly=false;
      var sessionsUserPage=1,sessionsUserPs={{.DefaultPageSize}};
      function renderSessionsUserPager(vis){
        var bar=document.getElementById('sessions-user-pagination');
        if(!bar)return;
        var total=vis.length,totalPages=Math.max(1,Math.ceil(total/sessionsUserPs));
        if(sessionsUserPage>totalPages)sessionsUserPage=1;
        var start=(sessionsUserPage-1)*sessionsUserPs;
        var allRows=Array.from(document.querySelectorAll('#user-sessions-table .sessions-table-row'));
        allRows.forEach(function(r){r.style.display='none';});
        vis.slice(start,start+sessionsUserPs).forEach(function(r){r.style.display='';});
        if(totalPages<=1&&total>0){bar.innerHTML='';vis.forEach(function(r){r.style.display='';});return;}
        if(total===0){bar.innerHTML='';return;}
        bar.innerHTML='<button class="pagination-btn" '+(sessionsUserPage<=1?'disabled':'')+'>&#8592;</button><span class="pagination-info">'+(start+1)+'&#8211;'+Math.min(start+sessionsUserPs,total)+' of '+total+'</span><button class="pagination-btn" '+(sessionsUserPage>=totalPages?'disabled':'')+'>&#8594;</button><select class="pagination-size-select">'+[15,30,50,100].map(function(n){return'<option value="'+n+'"'+(n===sessionsUserPs?' selected':'')+'>'+n+' per page</option>';}).join('')+'</select>';
        var btns=bar.querySelectorAll('.pagination-btn');
        if(!btns[0].disabled)btns[0].addEventListener('click',function(){sessionsUserPage--;filterUser();});
        if(!btns[1].disabled)btns[1].addEventListener('click',function(){sessionsUserPage++;filterUser();});
        bar.querySelector('.pagination-size-select').addEventListener('change',function(){sessionsUserPs=parseInt(this.value);sessionsUserPage=1;filterUser();});
      }
      function filterUser(){
        var hostFilter='';
        var hi=document.querySelector('#user-sessions-table .gtcol-filter-input[data-col="shost"]');
        if(hi) hostFilter=hi.value.toLowerCase().trim();
        var allRows=Array.from(document.querySelectorAll('#user-sessions-table .sessions-table-row'));
        var vis=allRows.filter(function(row){
          if(hostFilter){var hc=row.querySelector('.gtcol-shost');if(hc&&hc.textContent.toLowerCase().indexOf(hostFilter)===-1){return false;}}
          if(activeOnly&&row.dataset.active!=='true'){return false;}
          return true;
        });
        renderSessionsUserPager(vis);
      }
      var hi=document.querySelector('#user-sessions-table .gtcol-filter-input[data-col="shost"]');
      if(hi) hi.addEventListener('input',function(){sessionsUserPage=1;filterUser();});
      (function(){var ftb=document.getElementById('user-sessions-filter-toggle');var ftr=document.getElementById('user-sessions-filter-row');if(ftr&&ftr.style.display==='none'&&hi&&hi.value){ftr.style.display='';if(ftb)ftb.classList.add('active');}if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      var aot=document.getElementById('active-only-toggle');
      if(aot){
        function toggleAO(){activeOnly=!activeOnly;aot.classList.toggle('active',activeOnly);aot.setAttribute('aria-checked',activeOnly?'true':'false');sessionsUserPage=1;filterUser();}
        aot.addEventListener('click',toggleAO);
        aot.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleAO();}});
      }
      document.querySelectorAll('#user-sessions-table .saction-confirm').forEach(function(btn){
        btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});
      });
      document.querySelectorAll('.elevate-toggle').forEach(function(btn){
        btn.addEventListener('click',function(e){e.stopPropagation();var m=btn.parentElement.querySelector('.elevate-menu');var open=m.classList.contains('open');document.querySelectorAll('.elevate-menu.open').forEach(function(x){x.classList.remove('open');});if(!open){var r=btn.getBoundingClientRect();m.style.top=(r.bottom+4)+'px';m.style.right=(window.innerWidth-r.right)+'px';m.style.left='auto';m.classList.add('open');}});
      });
      document.addEventListener('click',function(){document.querySelectorAll('.elevate-menu.open').forEach(function(m){m.classList.remove('open');});});
      filterUser();
    })();
    // L5: prevent double-submit on approve/reject forms — intercept click, not submit
    document.querySelectorAll('.list form, .bulk-row form').forEach(function(f){
      var btn=f.querySelector('button[type=submit]');
      if(!btn)return;
      btn.addEventListener('click',function(e){
        if(btn.dataset.confirm){if(!confirm(btn.dataset.confirm)){return;}}
        e.preventDefault();
        btn.disabled=true;
        f.submit();
      });
    });
    </script>
    {{end}}{{/* end non-admin branch */}}
    {{if .HighlightHost}}
    <script nonce="{{.CSPNonce}}">
    (function(){var el=document.querySelector('.session-highlight');if(el){el.scrollIntoView({behavior:'smooth',block:'center'});}})();
    </script>
    {{end}}

  </main>
</body>
</html>`

const historyPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{call .T "history"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- auto-refresh removed: use SSE or fetch-based refresh instead to avoid resetting unsaved state -->
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 28 28' fill='none'%3E%3Ccircle cx='14' cy='5' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='8.5' x2='14' y2='13' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='7' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='21' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='7' cy='21' r='3.5' fill='%23a855f7'/%3E%3Ccircle cx='21' cy='21' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='13' x2='14' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='14' cy='21' r='3.5' fill='%23a855f7'/%3E%3C/svg%3E">
  <style>` + sharedCSS + navCSS + `
    .history-action.approved { color: var(--success); }
    .history-action.revoked, .history-action.rejected { color: var(--danger); }
    .history-action.auto_approved, .history-action.elevated, .history-action.extended { color: var(--primary); }
    .history-action.rotated_breakglass { color: var(--text-2); }
    .history-actor { font-size: 0.6875rem; color: var(--text-2); font-weight: 400; }
    .export-links { margin-left: auto; font-size: 0.6875rem; }
    .export-link { color: var(--text-2); text-decoration: none; padding: 0 4px; }
    .export-link:hover { color: var(--primary); text-decoration: underline; }
    .pagination { display: flex; justify-content: center; align-items: center; gap: 16px; margin-top: 16px; font-size: 0.875rem; flex-wrap: wrap; }
    .pagination a { color: var(--primary); text-decoration: none; font-weight: 600; }
    .pagination a:hover { text-decoration: underline; }
    .page-info { color: var(--text-2); }
    .page-size-form { display: inline-flex; align-items: center; gap: 4px; }
    .page-size-form select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.8125rem; background: var(--surface); color: var(--text); }
    .page-size-btn { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.8125rem; background: var(--surface); color: var(--text); cursor: pointer; }
    .page-size-btn:hover { background: var(--surface-2); }
    .history-gtable { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 4px; }
    {{if .IsAdmin}}
    .history-gtable-header, .history-gtable-filter, .history-gtable-row { display: grid; grid-template-columns: 200px 1.2fr 1fr 1.3fr 1fr 1.5fr; gap: 0; padding-left: 4px; padding-right: 4px; }
    {{else}}
    .history-gtable-header, .history-gtable-filter, .history-gtable-row { display: grid; grid-template-columns: 200px 1.3fr 1.5fr 1fr 1.5fr; gap: 0; padding-left: 4px; padding-right: 4px; }
    {{end}}
    .history-gtable-header { padding-top: 8px; padding-bottom: 8px; background: var(--surface-2); border-bottom: 1px solid var(--border); align-items: center; }
    .history-gtable-filter { padding-top: 5px; padding-bottom: 5px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .history-gtable-row { padding-top: 9px; padding-bottom: 9px; border-bottom: 1px solid var(--border); align-items: center; }
    .history-gtable-row:last-child { border-bottom: none; }
    .history-gtable-row:hover { background: var(--surface-2); }
    .timeline { margin: 0 0 20px; }
    .timeline-bars { display: flex; align-items: flex-end; gap: 2px; height: 40px; }
    .timeline-bar { flex: 1; background: var(--primary); border-radius: 2px 2px 0 0; min-height: 2px; opacity: 0.35; transition: opacity 0.15s, transform 0.15s; cursor: pointer; text-decoration: none; display: block; }
    .timeline-bar:hover { opacity: 0.9; transform: scaleY(1.08); transform-origin: bottom; }
    .timeline-bar.now { background: var(--success); opacity: 0.7; }
    .timeline-bar.timeline-active { opacity: 1; outline: 2px solid var(--primary); outline-offset: 1px; }
    .timeline-bar.timeline-active.now { outline-color: var(--success); }
    .timeline-axis { position: relative; height: 16px; margin-top: 3px; }
    .timeline-axis-label { position: absolute; font-size: 0.6875rem; color: var(--text-3); transform: translateX(-50%); white-space: nowrap; }
    .time-range-form { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 7px; background: var(--surface-2); border: 1px solid var(--border); margin-bottom: 12px; font-size: 0.8125rem; color: var(--text-2); flex-wrap: wrap; }
    .time-range-form label { font-weight: 500; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.04em; font-size: 0.75rem; white-space: nowrap; }
    .time-range-form input[type="datetime-local"] { background: var(--surface); border: 1px solid var(--border); border-radius: 5px; color: var(--text); font-size: 0.8125rem; padding: 3px 7px; font-family: inherit; min-width: 160px; }
    .time-range-form input[type="datetime-local"]:focus { outline: none; border-color: var(--primary); }
    .time-range-form .time-range-sep { color: var(--text-3); font-size: 0.75rem; }
    .time-range-form .time-range-apply { padding: 4px 12px; border-radius: 5px; background: var(--primary-sub); color: var(--primary); border: 1px solid var(--primary); font-size: 0.8125rem; font-weight: 500; cursor: pointer; font-family: inherit; white-space: nowrap; }
    .time-range-form .time-range-apply:hover { background: var(--primary); color: #fff; }
    .time-range-form .time-range-clear { color: var(--text-3); text-decoration: none; font-size: 0.75rem; padding: 4px 8px; border-radius: 5px; border: 1px solid transparent; white-space: nowrap; }
    .time-range-form .time-range-clear:hover { color: var(--danger); border-color: var(--danger); }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    document.querySelectorAll('.user-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var open=btn.classList.contains('open');
        document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});
        if(!open){btn.classList.add('open');btn.setAttribute('aria-expanded','true');}
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});});
    (function(){
      var axisEl=document.getElementById('timeline-axis');
      var barsEl=document.getElementById('timeline-bars');
      if(!axisEl||!barsEl)return;
      var bars=Array.from(barsEl.querySelectorAll('.timeline-bar'));
      if(!bars.length)return;
      [{h:24,label:'24h ago'},{h:18,label:'18h'},{h:12,label:'12h'},{h:6,label:'6h'},{h:0,label:'now'}].forEach(function(m){
        var best=null,bestDiff=Infinity;
        bars.forEach(function(b){var d=Math.abs(parseInt(b.dataset.hoursAgo||'0')-m.h);if(d<bestDiff){bestDiff=d;best=b;}});
        if(!best)return;
        var bRect=best.getBoundingClientRect(),cRect=barsEl.getBoundingClientRect();
        var pct=((bRect.left+bRect.width/2-cRect.left)/cRect.width*100).toFixed(1);
        var lbl=document.createElement('span');
        lbl.className='timeline-axis-label';lbl.style.left=pct+'%';lbl.textContent=m.label;
        axisEl.appendChild(lbl);
      });
    })();
    (function(){
      var ftb=document.getElementById('history-filter-toggle');
      var ftr=document.getElementById('history-filter-row');
      var ffc=document.getElementById('history-filter-clear');
      var hjmt=document.getElementById('history-just-me-toggle');
      var historyJustMeActive=false;
      var historyJustMeUsername=hjmt?hjmt.dataset.username||'':'';
      function showFilter(){if(ftr){ftr.style.display='';if(ftb)ftb.classList.add('active');}}
      function hideFilter(){if(ftr){ftr.style.display='none';if(ftb)ftb.classList.remove('active');}}
      if(ftb)ftb.addEventListener('click',function(){var shown=ftr&&ftr.style.display!=='none';if(shown)hideFilter();else{showFilter();var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});
      // Auto-expand and pre-fill when linked with server-side filters
      if(ftr){
        var ph=ftr.dataset.prefilterHost||'';var pu=ftr.dataset.prefilterUser||'';var pa=ftr.dataset.prefilterAction||'';
        if(ph||pu||pa){
          showFilter();
          if(ph){var hi=ftr.querySelector('.gtcol-filter-input[data-col="hhost"]');if(hi)hi.value=ph;}
          if(pu){var ui=ftr.querySelector('.gtcol-filter-input[data-col="huser"]');if(ui)ui.value=pu;}
          if(pa){var ai=ftr.querySelector('.gtcol-filter-input[data-col="haction"]');if(ai)ai.value=pa;}
        }
      }
      function filterHistory(){
        var filters={};
        document.querySelectorAll('#history-gtable .gtcol-filter-input').forEach(function(inp){filters[inp.dataset.col]=inp.value.toLowerCase().trim();});
        var visibleCount=0;
        document.querySelectorAll('.history-gtable-row').forEach(function(row){
          var show=true;
          for(var col in filters){if(!filters[col])continue;var cell=row.querySelector('.gtcol-'+col);if(cell&&cell.textContent.toLowerCase().indexOf(filters[col])===-1){show=false;break;}}
          if(show&&historyJustMeActive&&historyJustMeUsername){var pill=row.querySelector('.gtcol-huser .pill');if(!pill||pill.textContent.trim()!==historyJustMeUsername)show=false;}
          row.style.display=show?'':'none';
          if(show)visibleCount++;
        });
        var emptyMsg=document.getElementById('filter-empty-msg');
        if(emptyMsg){emptyMsg.style.display=visibleCount===0?'':'none';}
      }
      if(hjmt){
        function toggleHistoryJM(){historyJustMeActive=!historyJustMeActive;hjmt.classList.toggle('active',historyJustMeActive);hjmt.setAttribute('aria-checked',historyJustMeActive?'true':'false');filterHistory();}
        hjmt.addEventListener('click',toggleHistoryJM);
        hjmt.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleHistoryJM();}});
      }
      document.querySelectorAll('#history-gtable .gtcol-filter-input').forEach(function(inp){inp.addEventListener('input',filterHistory);});
      if(ffc)ffc.addEventListener('click',function(){document.querySelectorAll('#history-gtable .gtcol-filter-input').forEach(function(inp){inp.value='';});filterHistory();});
    })();
  });
  // Poll every 30 seconds and reload if no unsaved filter state; preserve active filter inputs via sessionStorage
  (function(){
    var FILTER_KEY='identree_history_filters';
    // Restore filter state saved before the last auto-reload
    try{
      var saved=sessionStorage.getItem(FILTER_KEY);
      if(saved){
        sessionStorage.removeItem(FILTER_KEY);
        var vals=JSON.parse(saved);
        document.querySelectorAll('#history-gtable .gtcol-filter-input').forEach(function(inp){
          if(vals[inp.dataset.col]){inp.value=vals[inp.dataset.col];}
        });
        // Trigger filter re-evaluation after restore (filterHistory is defined inside DOMContentLoaded scope;
        // fire input events so the already-registered listeners pick up the restored values)
        document.querySelectorAll('#history-gtable .gtcol-filter-input').forEach(function(inp){
          if(inp.value){inp.dispatchEvent(new Event('input'));}
        });
        // Expand filter row if any values were restored
        var ftr=document.getElementById('history-filter-row');
        var ftb=document.getElementById('history-filter-toggle');
        if(ftr&&ftr.style.display==='none'){ftr.style.display='';if(ftb)ftb.classList.add('active');}
      }
    }catch(e){}
    setInterval(function(){
      if(document.querySelector('form.dirty'))return;
      // Check for active filter inputs — if any are set, save them and restore after reload
      var filterVals={};
      var hasFilter=false;
      document.querySelectorAll('#history-gtable .gtcol-filter-input').forEach(function(inp){
        if(inp.value){filterVals[inp.dataset.col]=inp.value;hasFilter=true;}
      });
      if(hasFilter){
        try{sessionStorage.setItem(FILTER_KEY,JSON.stringify(filterVals));}catch(e){}
      }
      fetch(window.location.href,{method:'HEAD'}).then(function(r){
        if(r.status===401){window.location.href='/login';return;}
        location.reload();
      }).catch(function(){
        // On network error, clear the saved state so stale values don't linger
        try{sessionStorage.removeItem(FILTER_KEY);}catch(e){}
      });
    },30000);
  })();
  </script>
</head>
<body class="app{{if .Pending}} has-pending{{end}}">
  <a href="#main-content" class="skip-link">{{call .T "skip_to_content"}}</a>` + pendingBarHTML + `
  <nav class="sidebar" aria-label="Main navigation">
    <div class="sidebar-brand">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 28 28" fill="none" aria-hidden="true"><circle cx="14" cy="5" r="3.5" fill="currentColor"/><line x1="14" y1="8.5" x2="14" y2="13" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="7" y2="18" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="21" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="21" r="3.5" fill="currentColor"/><circle cx="21" cy="21" r="3.5" fill="currentColor"/><line x1="14" y1="13" x2="14" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="14" cy="21" r="3.5" fill="currentColor"/></svg>
      {{call .T "app_name"}}
    </div>
    <div class="sidebar-nav">` + sidebarNavHTML + `
    </div>
    <div class="sidebar-footer">
      <div class="user-btn" tabindex="0" role="button" aria-label="{{call .T "aria_user_menu"}}" aria-haspopup="true" aria-expanded="false">
        <div class="user-avatar">{{if .Avatar}}<img src="{{.Avatar}}" alt="">{{else}}{{.Initial}}{{end}}</div>
        <div class="user-name-wrap"><span class="user-display-name">{{.Username}}{{if .IsAdmin}}<span class="user-role-badge">{{call .T "admin"}}</span>{{end}}</span></div>
        <div class="user-dropdown">
          <div class="user-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/history"><select name="lang" class="lang-select" aria-label="{{call .T "language"}}">{{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/history"><select name="tz" class="tz-select" aria-label="{{call .T "timezone"}}">` + tzOptionsHTML + `</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-opts">
            <a href="/theme?set=system&from=/history" class="theme-opt{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/history" class="theme-opt{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/history" class="theme-opt{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="user-dropdown-divider"></div>
          <form method="POST" action="/signout" style="display:inline;margin:0"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="csrf_ts" value="{{.CSRFTs}}"><button type="submit" class="user-dropdown-item" style="width:100%;text-align:left;background:none;border:none;cursor:pointer;color:var(--danger);font:inherit;font-size:0.8125rem;font-weight:500;padding:7px 14px">{{call .T "sign_out"}}</button></form>
        </div>
      </div>
    </div>
  </nav>
  <main class="main" id="main-content">
    <h1 class="sr-only">{{call .T "history"}} - {{call .T "app_name"}}</h1>


    {{if .Timeline}}
    <div class="timeline">
      <div class="timeline-bars" id="timeline-bars">
        {{range .Timeline}}<a href="/history?from={{.HourStartISO}}&to={{.HourEndISO}}&per_page={{$.PerPage}}&user={{$.UserFilter}}" class="timeline-bar{{if .IsNow}} now{{end}}{{if eqInt .HoursAgo $.ActiveHoursAgo}} timeline-active{{end}}" style="height:{{.Height}}px" title="{{.Details}}" aria-label="{{.Details}}" data-hours-ago="{{.HoursAgo}}"></a>{{end}}
      </div>
      <div class="timeline-axis" id="timeline-axis"></div>
    </div>
    {{end}}

    {{if or .FilterFrom .FilterTo}}
    <form method="GET" action="/history" class="time-range-form">
      <input type="hidden" name="q" value="{{.Query}}">
      <input type="hidden" name="action" value="{{.ActionFilter}}">
      <input type="hidden" name="hostname" value="{{.HostFilter}}">
      <input type="hidden" name="user" value="{{.UserFilter}}">
      <input type="hidden" name="sort" value="{{.Sort}}">
      <input type="hidden" name="order" value="{{.Order}}">
      <input type="hidden" name="per_page" value="{{.PerPage}}">
      <label for="history-from">{{call .T "history_from"}}</label>
      <input type="datetime-local" id="history-from" name="from" value="{{.FilterFrom}}">
      <span class="time-range-sep">→</span>
      <label for="history-to">To</label>
      <input type="datetime-local" id="history-to" name="to" value="{{.FilterTo}}">
      <button type="submit" class="time-range-apply">{{call .T "history_apply"}}</button>
      <a href="/history?q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}" class="time-range-clear">Clear</a>
    </form>
    {{end}}

    {{if .History}}
    <div class="history-gtable" id="history-gtable" role="table" aria-label="{{call .T "history"}}">
      <div class="history-gtable-header" role="row">
        <div class="gtcol gtcol-htime" role="columnheader" style="gap:8px;align-items:center"><button type="button" class="filter-toggle-btn" id="history-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button><a href="/history?sort=timestamp&order={{if eq .Sort "timestamp"}}{{if eq .Order "desc"}}asc{{else}}desc{{end}}{{else}}desc{{end}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="col-sort-link{{if eq .Sort "timestamp"}} active{{end}}">{{call .T "time"}}{{if eq .Sort "timestamp"}} {{if eq .Order "asc"}}↑{{else}}↓{{end}}{{end}}</a></div>
        <div class="gtcol gtcol-haction" role="columnheader"><a href="/history?sort=action&order={{if eq .Sort "action"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="col-sort-link{{if eq .Sort "action"}} active{{end}}">{{call .T "action"}}{{if eq .Sort "action"}} {{if eq .Order "asc"}}↑{{else}}↓{{end}}{{end}}</a></div>
        {{if .IsAdmin}}<div class="gtcol gtcol-huser" role="columnheader" style="gap:8px;align-items:center"><a href="/history?sort=user&order={{if eq .Sort "user"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="col-sort-link{{if eq .Sort "user"}} active{{end}}">{{call .T "user"}}{{if eq .Sort "user"}} {{if eq .Order "asc"}}↑{{else}}↓{{end}}{{end}}</a><div class="toggle-wrap" id="history-just-me-toggle" role="switch" aria-checked="false" tabindex="0" data-username="{{.Username}}"><span>{{call .T "just_me"}}</span><div class="toggle-track"><div class="toggle-thumb"></div></div></div></div>{{end}}
        <div class="gtcol gtcol-hhost" role="columnheader"><a href="/history?sort=hostname&order={{if eq .Sort "hostname"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="col-sort-link{{if eq .Sort "hostname"}} active{{end}}">{{call .T "host"}}{{if eq .Sort "hostname"}} {{if eq .Order "asc"}}↑{{else}}↓{{end}}{{end}}</a></div>
        <div class="gtcol gtcol-hcode" role="columnheader"><a href="/history?sort=code&order={{if eq .Sort "code"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="col-sort-link{{if eq .Sort "code"}} active{{end}}">{{call .T "code"}}{{if eq .Sort "code"}} {{if eq .Order "asc"}}↑{{else}}↓{{end}}{{end}}</a></div>
        <div class="gtcol gtcol-hreason" role="columnheader"><span class="col-sort-link">{{call .T "reason"}}</span></div>
      </div>
      <div class="history-gtable-filter" id="history-filter-row" style="display:none" data-prefilter-host="{{.HostFilter}}" data-prefilter-user="{{.UserFilter}}" data-prefilter-action="{{.ActionFilter}}">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="htime" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="haction" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        {{if .IsAdmin}}<div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="huser" placeholder="{{call .T "search"}}…" autocomplete="off"></div>{{end}}
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="hhost" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div style="display:flex;justify-content:flex-end;align-items:center;padding:0 6px"><button type="button" class="filter-clear-btn" id="history-filter-clear">{{call .T "clear_filter"}}</button></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="hreason" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
      </div>
      {{range .History}}
      <div class="history-gtable-row" role="row">
        <div class="gtcol gtcol-htime" role="cell">
          <span style="font-size:0.8125rem">{{.FormattedTime}} <span class="time-ago" style="font-size:0.75rem;color:var(--text-3)">({{.TimeAgo}})</span></span>
        </div>
        <div class="gtcol gtcol-haction" role="cell" style="align-items:center;flex-wrap:wrap;gap:3px">
          <span class="history-action {{.Action}}" style="font-size:0.8125rem">{{.ActionLabel}}{{if .Actor}} <span class="history-actor">({{call $.T "by"}} {{.Actor}})</span>{{end}}</span>
        </div>
        {{if $.IsAdmin}}<div class="gtcol gtcol-huser" role="cell" style="align-items:center">{{if .Username}}<a href="/access?user={{.Username}}" class="pill user">{{.Username}}</a>{{end}}</div>{{end}}
        <div class="gtcol gtcol-hhost" role="cell" style="align-items:center">{{if .Hostname}}<a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a>{{end}}</div>
        <div class="gtcol gtcol-hcode" role="cell" style="font-family:monospace;font-size:0.8125rem;color:var(--text-2);align-items:center">{{if .Code}}{{.Code}}{{end}}</div>
        <div class="gtcol gtcol-hreason" role="cell" style="font-size:0.8125rem;color:var(--text-2);font-style:italic;align-items:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{if .Reason}}"{{.Reason}}"{{end}}</div>
      </div>
      {{end}}
    </div>
    <div id="filter-empty-msg" style="display:none" class="empty-state">No results match your filter</div>
    <div class="pagination">
      {{if .HasPrev}}<a href="/history?page={{sub .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">&#8592; {{call .T "previous"}}</a>{{end}}
      <span class="page-info">{{call .T "page"}} {{.Page}} {{call .T "of"}} {{.TotalPages}}</span>
      {{if .HasNext}}<a href="/history?page={{add .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">{{call .T "next"}} &#8594;</a>{{end}}
      <form method="GET" action="/history" class="page-size-form">
        <input type="hidden" name="action" value="{{.ActionFilter}}">
        <input type="hidden" name="hostname" value="{{.HostFilter}}">
        <input type="hidden" name="user" value="{{.UserFilter}}">
        <input type="hidden" name="sort" value="{{.Sort}}">
        <input type="hidden" name="order" value="{{.Order}}">
        <input type="hidden" name="q" value="{{.Query}}">
        <select name="per_page" class="page-size-select" aria-label="{{call .T "aria_page_size"}}">
          {{range .PerPageOptions}}<option value="{{.}}" {{if eqInt . $.PerPage}}selected{{end}}>{{.}}</option>{{end}}
        </select>
        <button type="submit" class="page-size-btn">{{call .T "go"}}</button>
      </form>
      <span class="export-links"><a href="/api/history/export?format=csv" class="export-link">{{call .T "export_csv"}}</a> <a href="/api/history/export?format=json" class="export-link">{{call .T "export_json"}}</a></span>
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_activity"}}</p>
    {{end}}
  </main>
</body>
</html>`



const adminPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{if .AdminTab}}{{.AdminTab}} - {{end}}{{call .T "admin"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- auto-refresh removed: use SSE or fetch-based refresh instead to avoid resetting unsaved form data -->
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 28 28' fill='none'%3E%3Ccircle cx='14' cy='5' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='8.5' x2='14' y2='13' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='7' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='21' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='7' cy='21' r='3.5' fill='%23a855f7'/%3E%3Ccircle cx='21' cy='21' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='13' x2='14' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='14' cy='21' r='3.5' fill='%23a855f7'/%3E%3C/svg%3E">
  <style>` + sharedCSS + navCSS + `
    .search-bar { margin-bottom: 16px; }
    .search-bar input[type="text"] { width: 100%; padding: 9px 13px; border: 1px solid var(--border); border-radius: 8px; font-size: 0.875rem; background: var(--surface); color: var(--text); outline: none; }
    .search-bar input[type="text"]:focus { border-color: var(--primary); box-shadow: var(--focus-ring); }
    .pagination { display: flex; justify-content: center; align-items: center; gap: 16px; margin-top: 16px; font-size: 0.875rem; flex-wrap: wrap; }
    .pagination a { color: var(--primary); text-decoration: none; font-weight: 600; }
    .pagination a:hover { text-decoration: underline; }
    .page-info { color: var(--text-2); }
    .page-size-form { display: inline-flex; align-items: center; gap: 4px; }
    .page-size-form select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.8125rem; background: var(--surface); color: var(--text); }
    .page-size-btn { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.8125rem; background: var(--surface); color: var(--text); cursor: pointer; }
    .page-size-btn:hover { background: var(--surface-2); }
    .history-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; table-layout: fixed; }
    .history-table th { padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 0.6875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.09em; color: var(--text-3); white-space: nowrap; overflow: hidden; }
    .history-table .col-time { width: 22%; }
    .history-table .col-action { width: 18%; }
    .history-table .col-user { width: 14%; }
    .history-table .col-host { width: 20%; }
    .history-table .col-code { width: 20%; }
    .history-table th a { color: var(--text-3); text-decoration: none; font-size: 0.75rem; text-transform: none; }
    .history-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .history-table tbody tr:hover td { background: var(--surface-2); }
    .col-time { white-space: nowrap; }
    .col-host { overflow: hidden; text-overflow: ellipsis; max-width: 200px; }
    .col-code { font-family: monospace; font-size: 0.8125rem; color: var(--text-2); white-space: nowrap; }
    .col-filter-form { display: inline-flex; align-items: center; gap: 2px; margin: 0; padding: 0; text-transform: none; max-width: 100%; }
    .sort-btn { display: inline-block; padding: 3px 5px; margin-left: 3px; color: var(--text-3); text-decoration: none; font-size: 0.75rem; border-radius: 4px; }
    .sort-btn:hover { color: var(--text); background: var(--surface-2); }
    .sort-btn.active { color: var(--primary); }
    .col-filter-select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.75rem; background: var(--surface); color: var(--text); cursor: pointer; max-width: 120px; width: auto; appearance: none; -webkit-appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 5l3 3 3-3' fill='none' stroke='%236b7280' stroke-width='1.5'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 6px center; padding-right: 22px; outline: none; }
    .col-filter-select:focus { border-color: var(--primary); }
    .history-action.approved { color: var(--success); }
    .history-action.revoked, .history-action.rejected { color: var(--danger); }
    .history-action.auto_approved, .history-action.elevated, .history-action.extended { color: var(--primary); }
    .history-action.rotated_breakglass { color: var(--text-2); }
    .history-actor { font-size: 0.6875rem; color: var(--text-2); font-weight: 400; }
    .saction-btn { display: inline-flex; align-items: center; gap: 5px; padding: 5px 11px; border-radius: 6px; font-size: 0.8125rem; font-weight: 500; border: 1px solid var(--border); background: var(--surface); color: var(--text-2); cursor: pointer; transition: background 0.15s, color 0.15s, border-color 0.15s; line-height: 1.4; white-space: nowrap; text-decoration: none; }
    .saction-btn:hover { background: var(--surface-2); color: var(--text); border-color: var(--text-3); }
    .saction-btn.saction-danger { color: var(--danger); }
    .saction-btn.saction-danger:hover { background: rgba(220,53,69,0.08); border-color: var(--danger); }
    .saction-btn.saction-primary { color: var(--primary); }
    .saction-btn.saction-primary:hover { background: var(--primary-sub); border-color: rgba(124,58,237,0.4); }
    .saction-btn.saction-sessions { min-width: 9rem; justify-content: center; }
    /* Config page */
    .config-table { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 20px; }
    .config-filter-header { display: flex; align-items: center; gap: 8px; padding: 7px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .config-filter-row { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--border); background: var(--bg); }
    .config-filter-row input { flex: 1; padding: 4px 8px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text); font-size: 0.8125rem; font-family: inherit; }
    .config-filter-row input:focus { outline: none; border-color: var(--primary); }
    .config-section-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); border-top: 1px solid var(--border); }
    .config-section-title { font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.09em; color: var(--text-3); }
    .config-table-row { display: flex; align-items: flex-start; gap: 16px; padding: 10px 12px; border-bottom: 1px solid var(--border); }
    .config-table-row:last-child { border-bottom: none; }
    .config-table-row.cfg-hidden { display: none; }
    .config-row-label { flex: 0 0 260px; min-width: 0; }
    .config-row-control { flex: 1; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding-top: 2px; }
    .config-locked { opacity: 0.55; }
    .config-label-text { font-size: 0.875rem; font-weight: 500; color: var(--text); }
    .config-label-env { font-size: 0.68rem; color: var(--text-3); font-family: monospace; margin-top: 2px; }
    .config-label-desc { font-size: 0.75rem; color: var(--text-2); margin-top: 4px; line-height: 1.4; }
    .config-input { padding: 5px 8px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text); font-size: 0.875rem; font-family: inherit; width: 100%; max-width: 480px; box-sizing: border-box; }
    .config-input:focus { outline: none; border-color: var(--primary); }
    .config-input:disabled { background: var(--surface-2); color: var(--text-3); cursor: not-allowed; }
    .config-select { padding: 5px 8px; border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text); font-size: 0.875rem; font-family: inherit; min-width: 160px; }
    .config-select:disabled { background: var(--surface-2); color: var(--text-3); cursor: not-allowed; }
    .config-secret-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; border: 1px solid var(--border); color: var(--text-3); background: var(--surface-2); }
    .config-secret-badge.configured { color: var(--success); background: var(--success-bg); border-color: var(--success-border); }
    .config-env-note { font-size: 0.8125rem; color: var(--text-3); display: flex; align-items: center; gap: 6px; margin-bottom: 14px; padding: 8px 12px; background: var(--surface-2); border-radius: 8px; border: 1px solid var(--border); }
    .config-save-btn { padding: 3px 10px; font-size: 0.75rem; }
    .config-section-dirty { position: relative; }
    .config-section-dirty .config-section-title::after { content: "unsaved"; font-size: 0.65rem; font-weight: 600; color: var(--warning,#d97706); background: rgba(217,119,6,0.12); border: 1px solid rgba(217,119,6,0.3); border-radius: 4px; padding: 1px 5px; margin-left: 8px; text-transform: uppercase; letter-spacing: 0.05em; vertical-align: middle; }
    .banner-restart { background: rgba(217,119,6,0.1); border: 1px solid rgba(217,119,6,0.35); color: var(--text); border-radius: 8px; padding: 10px 14px; margin-bottom: 10px; font-size: 0.875rem; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .banner-restart-icon { color: #d97706; flex-shrink: 0; }
    .banner-restart-text { flex: 1; min-width: 0; }
    .banner-restart-sections { font-weight: 600; color: #d97706; }
    .banner-restart-btn { display: inline-flex; align-items: center; gap: 5px; padding: 4px 12px; border-radius: 6px; font-size: 0.8125rem; font-weight: 600; border: 1px solid rgba(217,119,6,0.5); background: rgba(217,119,6,0.12); color: #d97706; cursor: pointer; transition: background 0.15s; white-space: nowrap; }
    .banner-restart-btn:hover { background: rgba(217,119,6,0.22); }
    /* Info grid table */
    .info-gtable { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 24px; }
    .info-gtable-header { display: grid; grid-template-columns: 220px 1fr; gap: 0; padding: 8px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.09em; color: var(--text-3); align-items: center; }
    .info-gtable-row { display: grid; grid-template-columns: 220px 1fr; gap: 0; padding: 9px 12px; border-bottom: 1px solid var(--border); align-items: center; font-size: 0.875rem; }
    .info-gtable-row:last-child { border-bottom: none; }
    .info-gtable-label { color: var(--text-2); }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  var _t={copied:'{{call .T "copied"}}',deployOk:'{{call .T "deploy_success"}}',deployFailed:'{{call .T "deploy_failed"}}',requestFailed:'{{call .T "request_failed"}}',clipboardEmpty:'{{call .T "clipboard_empty"}}',clipboardError:'{{call .T "clipboard_error"}}',loadingUsers:'{{call .T "deploy_user_loading"}}',unavailable:'{{call .T "deploy_user_unavailable"}}',deployRun:'{{call .T "deploy_run"}}',starting:'{{call .T "deploy_starting"}}',hostRequired:'{{call .T "host_required"}}',keyRequired:'{{call .T "key_required"}}',connLost:'{{call .T "connection_lost"}}',deployForbidden:'{{call .T "deploy_forbidden"}}'};
  var _csrf={'X-CSRF-Token':'{{.CSRFToken}}','X-CSRF-Ts':'{{.CSRFTs}}'};
  document.addEventListener('DOMContentLoaded',function(){
    // Auto-dismiss success banners after 5 seconds
    document.querySelectorAll('.banner-success').forEach(function(el){
      setTimeout(function(){el.style.transition='opacity 0.4s';el.style.opacity='0';setTimeout(function(){el.style.display='none';},400);},5000);
    });
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    var searchInput=document.querySelector('.search-bar input[name="q"]');
    if(searchInput){
      searchInput.addEventListener('input',function(){
        var q=this.value.toLowerCase();
        document.querySelectorAll('.history-table tbody tr,.users-table tbody tr,.groups-table-row').forEach(function(row){
          var text=row.textContent.toLowerCase();
          row.style.display=text.indexOf(q)!==-1?'':'none';
        });
      });
    }
    document.querySelectorAll('.user-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var open=btn.classList.contains('open');
        document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});
        if(!open){btn.classList.add('open');btn.setAttribute('aria-expanded','true');}
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});});
    // Script preview toggle + copy
    var scriptPreview=document.getElementById('deploy-script-preview');
    var scriptToggle=document.getElementById('deploy-script-toggle');
    var scriptContent=document.getElementById('deploy-script-content');
    var scriptCopyBtn=document.getElementById('deploy-script-copy-btn');
    var scriptFetched=false;
    if(scriptToggle){
      scriptToggle.addEventListener('click',function(e){
        if(e.target===scriptCopyBtn||scriptCopyBtn.contains(e.target)) return;
        scriptPreview.classList.toggle('open');
        if(scriptPreview.classList.contains('open')&&!scriptFetched){
          scriptFetched=true;
          fetch('/install.sh').then(function(r){return r.text();}).then(function(t){
            scriptContent.textContent=t;
          }).catch(function(){scriptContent.textContent='(failed to load)';});
        }
      });
      scriptToggle.addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();scriptToggle.click();}});
    }
    if(scriptCopyBtn){
      scriptCopyBtn.addEventListener('click',function(e){
        e.stopPropagation();
        var cmd=scriptCopyBtn.getAttribute('data-cmd');
        var orig=scriptCopyBtn.innerHTML;
        navigator.clipboard.writeText(cmd).then(function(){
          scriptCopyBtn.innerHTML='&#10003; '+_t.copied;
          setTimeout(function(){scriptCopyBtn.innerHTML=orig;},2000);
        }).catch(function(){
          var ta=document.createElement('textarea');
          ta.value=cmd;ta.style.position='fixed';ta.style.opacity='0';
          document.body.appendChild(ta);ta.select();
          try{document.execCommand('copy');scriptCopyBtn.innerHTML='&#10003; '+_t.copied;}catch(e){}
          document.body.removeChild(ta);
          setTimeout(function(){scriptCopyBtn.innerHTML=orig;},2000);
        });
      });
    }
    // Deploy modal
    var deployOpenBtn=document.getElementById('deploy-open-btn');
    var deployModal=document.getElementById('deploy-modal');
    var deployCancelBtn=document.getElementById('deploy-cancel-btn');
    var deploySubmitBtn=document.getElementById('deploy-submit-btn');
    var deployCloseBtn=document.getElementById('deploy-close-btn');
    var deployPrivKey=''; // in-memory only, never written to DOM

    function deployCheckReady(){
      var host=document.getElementById('deploy-host').value.trim();
      if(deploySubmitBtn) deploySubmitBtn.disabled=!(host && deployPrivKey);
    }

    function deployResetKey(){
      deployPrivKey='';
      document.getElementById('deploy-key-empty').style.display='';
      document.getElementById('deploy-key-loaded').style.display='none';
      document.getElementById('deploy-key-validating').style.display='none';
      document.getElementById('deploy-key-invalid').style.display='none';
      document.getElementById('deploy-key-file').value='';
      deployCheckReady();
    }

    function deployValidateKey(pem){
      document.getElementById('deploy-key-validating').style.display='';
      document.getElementById('deploy-key-invalid').style.display='none';
      fetch('/api/deploy/pubkey',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_csrf),body:JSON.stringify({private_key:pem})})
      .then(function(r){
        if(r.status===401){window.location.href='/login';return;}
        if(!r.ok){return r.text().then(function(t){throw new Error(t||r.statusText);});}
        return r.json();
      })
      .then(function(d){
        deployPrivKey=pem;
        document.getElementById('deploy-key-validating').style.display='none';
        document.getElementById('deploy-key-empty').style.display='none';
        document.getElementById('deploy-key-type').textContent=d.type;
        document.getElementById('deploy-key-fp').textContent=d.fingerprint;
        document.getElementById('deploy-key-loaded').style.display='';
        deployCheckReady();
      })
      .catch(function(err){
        deployPrivKey='';
        document.getElementById('deploy-key-validating').style.display='none';
        var inv=document.getElementById('deploy-key-invalid');
        inv.textContent=err.message||'Invalid key';
        inv.style.display='';
        if(deploySubmitBtn) deploySubmitBtn.disabled=true;
      });
    }

    var _deployPrevFocus=null;
    function openDeployModal(){
      _deployPrevFocus=document.activeElement;
      deployModal.classList.add('open');
      document.getElementById('deploy-form-area').style.display='';
      document.getElementById('deploy-log-area').style.display='none';
      document.getElementById('deploy-error').style.display='none';
      document.getElementById('deploy-log').textContent='';
      document.getElementById('deploy-status').textContent='';
      document.getElementById('deploy-status').className='deploy-status';
      deployResetKey();
      // Focus first field
      setTimeout(function(){var h=document.getElementById('deploy-host');if(h)h.focus();},50);
      // Load identity provider users with SSH keys
      var _deployUsers=[];
      var sel=document.getElementById('deploy-pocketid-user');
      sel.innerHTML='<option value="">'+_t.loadingUsers+'</option>';
      fetch('/api/deploy/users').then(function(r){if(r.status===401){window.location.href='/login';return Promise.reject('401');}return r.json();}).then(function(users){
        _deployUsers=users||[];
        sel.innerHTML='<option value="">(none)</option>';
        _deployUsers.forEach(function(u){
          var o=document.createElement('option');
          o.value=u.username;
          o.textContent=u.username+(u.email?' \u2014 '+u.email:'');
          sel.appendChild(o);
        });
        sel.addEventListener('change',function(){
          var username=sel.value;
          var keysEl=document.getElementById('deploy-user-keys');
          if(!username){keysEl.style.display='none';return;}
          var user=_deployUsers.find(function(u){return u.username===username;});
          if(!user||!user.ssh_keys||!user.ssh_keys.length){keysEl.style.display='none';return;}
          var list=document.getElementById('deploy-user-keys-list');
          list.innerHTML='';
          user.ssh_keys.forEach(function(k){
            var li=document.createElement('li');
            li.className='deploy-key-line';
            // Show key type + truncated key
            var parts=k.trim().split(/\s+/);
            var type=parts[0]||'';
            var body=parts[1]||'';
            var comment=parts.slice(2).join(' ');
            var short=body?body.slice(0,20)+'…'+body.slice(-8):'';
            li.textContent=type+(short?' '+short:'')+(comment?' '+comment:'');
            li.title=k;
            list.appendChild(li);
          });
          keysEl.style.display='';
        });
      }).catch(function(){sel.innerHTML='<option value="">'+_t.unavailable+'</option>';});
    }
    var deployDone=false;
    function closeDeployModal(){
      deployModal.classList.remove('open');
      if(_deployPrevFocus)_deployPrevFocus.focus();
    }
    if(deployOpenBtn){
      deployOpenBtn.addEventListener('click',openDeployModal);
      deployCancelBtn.addEventListener('click',closeDeployModal);
      deployCloseBtn.addEventListener('click',function(){
        if(deployDone)location.reload();
        else closeDeployModal();
      });
      deployModal.addEventListener('click',function(e){if(e.target===deployModal)closeDeployModal();});
      document.addEventListener('keydown',function(e){if(e.key==='Escape'&&deployModal.classList.contains('open'))closeDeployModal();});
      document.getElementById('deploy-host').addEventListener('input',deployCheckReady);
      // Paste key from clipboard
      document.getElementById('deploy-key-paste-btn').addEventListener('click',function(){
        navigator.clipboard.readText().then(function(text){
          if(text.trim()) deployValidateKey(text.trim());
          else{var inv=document.getElementById('deploy-key-invalid');inv.textContent=_t.clipboardEmpty;inv.style.display='';}
        }).catch(function(){
          var inv=document.getElementById('deploy-key-invalid');
          inv.textContent=_t.clipboardError;
          inv.style.display='';
        });
      });
      // Upload key from file
      document.getElementById('deploy-key-upload-btn').addEventListener('click',function(){
        document.getElementById('deploy-key-file').click();
      });
      document.getElementById('deploy-key-file').addEventListener('change',function(){
        var f=this.files[0];
        if(!f) return;
        var reader=new FileReader();
        reader.onload=function(e){deployValidateKey(e.target.result.trim());};
        reader.readAsText(f);
      });
      // Clear key
      document.getElementById('deploy-key-clear-btn').addEventListener('click',deployResetKey);
      // Submit
      deploySubmitBtn.addEventListener('click',function(){
        var host=document.getElementById('deploy-host').value.trim();
        var port=parseInt(document.getElementById('deploy-port').value)||22;
        var sshUser=document.getElementById('deploy-ssh-user').value.trim()||'root';
        var pocketidUser=document.getElementById('deploy-pocketid-user').value;
        var errEl=document.getElementById('deploy-error');
        if(!host){errEl.textContent=_t.hostRequired;errEl.style.display='';return;}
        if(!deployPrivKey){errEl.textContent=_t.keyRequired;errEl.style.display='';return;}
        errEl.style.display='none';
        deploySubmitBtn.disabled=true;
        deploySubmitBtn.textContent=_t.starting;
        fetch('/api/deploy',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_csrf),body:JSON.stringify({hostname:host,port:port,ssh_user:sshUser,private_key:deployPrivKey,pocketid_user:pocketidUser})})
        .then(function(r){
          if(r.status===401){window.location.href='/login';return;}
          if(!r.ok){if(r.status===403){throw new Error(_t.deployForbidden);}return r.text().then(function(t){throw new Error(t||r.statusText);});}
          return r.json();
        })
        .then(function(data){
          if(!data)return;
          deployPrivKey=''; // clear key from memory once submitted
          deploySubmitBtn.disabled=false;
          deploySubmitBtn.textContent=_t.deployRun;
          document.getElementById('deploy-form-area').style.display='none';
          document.getElementById('deploy-log-area').style.display='';
          var logEl=document.getElementById('deploy-log');
          var statusEl=document.getElementById('deploy-status');
          var es=new EventSource('/api/deploy/stream/'+data.id);
          var _deployUnload=function(){es.close();};
          window.addEventListener('beforeunload',_deployUnload);
          es.addEventListener('message',function(e){
            logEl.textContent+=e.data+'\n';
            logEl.scrollTop=logEl.scrollHeight;
          });
          es.addEventListener('status',function(e){
            es.close();
            window.removeEventListener('beforeunload',_deployUnload);
            if(e.data==='done'){statusEl.textContent='\u2713 '+_t.deployOk;statusEl.className='deploy-status ok';deployDone=true;}
            else{statusEl.textContent='\u2717 '+_t.deployFailed;statusEl.className='deploy-status err';}
          });
          es.onerror=function(){es.close();window.removeEventListener('beforeunload',_deployUnload);if(!statusEl.textContent){statusEl.textContent=_t.connLost;statusEl.className='deploy-status err';}};
        })
        .catch(function(err){
          deploySubmitBtn.disabled=false;
          deploySubmitBtn.textContent=_t.deployRun;
          errEl.textContent=err.message||_t.requestFailed;
          errEl.style.display='';
        });
      });
    }
  });
  document.addEventListener('click',function(e){
    var chip=e.target.closest('.summary-chip.expandable');
    if(!chip)return;
    var cell=chip.closest('.perms-cell');
    var listType=chip.classList.contains('commands')?'cmd':'host';
    var list=cell.querySelector('.expanded-list[data-type="'+listType+'"]');
    var open=list.classList.contains('visible');
    list.classList.toggle('visible',!open);
    chip.classList.toggle('open',!open);
  });
  document.querySelectorAll('.saction-btn[type=submit]:not(.config-save-btn)').forEach(function(btn){
    btn.addEventListener('click',function(e){
      if(btn.dataset.confirm){if(!confirm(btn.dataset.confirm)){return;}}
      e.preventDefault();
      btn.disabled=true;
      btn.style.opacity='0.6';
      btn.closest('form').submit();
    });
  });
  </script>
</head>
<body class="app{{if .Pending}} has-pending{{end}}">
  <a href="#main-content" class="skip-link">{{call .T "skip_to_content"}}</a>` + pendingBarHTML + `
  <nav class="sidebar" aria-label="Main navigation">
    <div class="sidebar-brand">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 28 28" fill="none" aria-hidden="true"><circle cx="14" cy="5" r="3.5" fill="currentColor"/><line x1="14" y1="8.5" x2="14" y2="13" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="7" y2="18" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="21" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="21" r="3.5" fill="currentColor"/><circle cx="21" cy="21" r="3.5" fill="currentColor"/><line x1="14" y1="13" x2="14" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="14" cy="21" r="3.5" fill="currentColor"/></svg>
      {{call .T "app_name"}}
    </div>
    <div class="sidebar-nav">` + sidebarNavHTML + `
    </div>
    <div class="sidebar-footer">
      <div class="user-btn" tabindex="0" role="button" aria-label="{{call .T "aria_user_menu"}}" aria-haspopup="true" aria-expanded="false">
        <div class="user-avatar">{{if .Avatar}}<img src="{{.Avatar}}" alt="">{{else}}{{.Initial}}{{end}}</div>
        <div class="user-name-wrap"><span class="user-display-name">{{.Username}}<span class="user-role-badge">{{call .T "admin"}}</span></span></div>
        <div class="user-dropdown">
          <div class="user-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/admin/{{.AdminTab}}"><select name="lang" class="lang-select" aria-label="{{call .T "language"}}">{{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/admin/{{.AdminTab}}"><select name="tz" class="tz-select" aria-label="{{call .T "timezone"}}">` + tzOptionsHTML + `</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-opts">
            <a href="/theme?set=system&from=/admin" class="theme-opt{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/admin" class="theme-opt{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/admin" class="theme-opt{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="user-dropdown-divider"></div>
          <form method="POST" action="/signout" style="display:inline;margin:0"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="csrf_ts" value="{{.CSRFTs}}"><button type="submit" class="user-dropdown-item" style="width:100%;text-align:left;background:none;border:none;cursor:pointer;color:var(--danger);font:inherit;font-size:0.8125rem;font-weight:500;padding:7px 14px">{{call .T "sign_out"}}</button></form>
        </div>
      </div>
    </div>
  </nav>
  <main class="main" id="main-content">
    <h1 class="sr-only">{{call .T "admin"}} - {{call .T "app_name"}}</h1>
    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}

    {{if eq .AdminTab "info"}}
    {{if .LDAPSyncError}}<div class="banner banner-warning">{{call .T "ldap_sync_error"}}: {{.LDAPSyncError}}</div>{{end}}
    <div class="info-gtable">
      <div class="info-gtable-header"><div>{{call .T "system_info"}}</div><div></div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "version"}}</div><div>{{.Version}}{{if .Commit}} <span style="color:var(--text-3);font-size:0.8rem;cursor:help" title="{{.Commit}}">({{.CommitShort}})</span>{{end}}</div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "uptime"}}</div><div>{{.Uptime}}</div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "go_version"}}</div><div>{{.GoVersion}}</div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "os_arch"}}</div><div>{{.OSArch}}</div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "goroutines"}}</div><div>{{.Goroutines}}</div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "memory_usage"}}</div><div>{{.MemUsage}}</div></div>
      <div class="info-gtable-row"><div class="info-gtable-label">{{call .T "active_sessions"}}</div><div>{{.ActiveSessionsCount}}</div></div>
    </div>

    {{else if eq .AdminTab "config"}}
    {{if .RestartSections}}<div class="banner-restart" role="alert"><svg class="banner-restart-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span class="banner-restart-text">Configuration saved. Changes to <span class="banner-restart-sections">{{range $i,$s := .RestartSections}}{{if $i}}, {{end}}{{$s}}{{end}}</span> require a server restart to take effect.</span><button type="button" class="banner-restart-btn" id="restart-server-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.5"/></svg>Restart server</button></div>{{end}}
    {{range .FlashErrors}}<div class="banner banner-error" role="alert">{{.}}</div>{{end}}
    <div class="config-env-note"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{call .T "env_locked_note"}}</div>
    <form method="POST" action="/admin/config" autocomplete="off">
    <input type="hidden" name="username" value="{{.Username}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
    <div class="config-table" id="config-table">
      <div class="config-filter-header">
        <button type="button" class="filter-toggle-btn" id="config-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button>
        <span class="config-section-title" style="margin-left:4px">{{call .T "config"}}</span>
      </div>
      <div class="config-filter-row" id="config-filter-row" style="display:none">
        <input type="text" id="config-filter-input" placeholder="Search settings…" autocomplete="off">
        <button type="button" class="filter-clear-btn" id="config-filter-clear">{{call .T "clear_filter"}}</button>
      </div>
    <!-- TODO: i18n — config help descriptions below are English-only. -->
    {{/* OIDC */}}
      <div class="config-section-row" data-section="oidc"><span class="config-section-title">{{call .T "cfg_oidc"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_OIDC_ISSUER_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_OIDC_ISSUER_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="oidc" data-search="IDENTREE_OIDC_ISSUER_URL Internal URL identree uses to reach Pocket ID (not browser-visible)."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_issuer_url"}}</div><div class="config-label-env">IDENTREE_OIDC_ISSUER_URL</div><div class="config-label-desc">Internal URL identree uses to reach Pocket ID (not browser-visible).</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_OIDC_ISSUER_URL" value="{{$v}}" class="config-input" placeholder="https://pocketid.example.com">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_OIDC_ISSUER_PUBLIC_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_OIDC_ISSUER_PUBLIC_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="oidc" data-search="IDENTREE_OIDC_ISSUER_PUBLIC_URL Public OIDC URL for browser redirects — only needed when internal and external URLs differ."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_issuer_public_url"}}</div><div class="config-label-env">IDENTREE_OIDC_ISSUER_PUBLIC_URL</div><div class="config-label-desc">Public OIDC URL for browser redirects — only needed when internal and external URLs differ.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_OIDC_ISSUER_PUBLIC_URL" value="{{$v}}" class="config-input" placeholder="https://pocketid.example.com">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_OIDC_CLIENT_ID"}}{{$lk:=index .ConfigLocked "IDENTREE_OIDC_CLIENT_ID"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="oidc" data-search="IDENTREE_OIDC_CLIENT_ID OAuth2 client ID of the identree application registered in Pocket ID."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_client_id"}}</div><div class="config-label-env">IDENTREE_OIDC_CLIENT_ID</div><div class="config-label-desc">OAuth2 client ID of the identree application registered in Pocket ID.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_OIDC_CLIENT_ID" value="{{$v}}" class="config-input">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_OIDC_CLIENT_SECRET"}}<div class="config-table-row config-locked" data-section="oidc" data-search="IDENTREE_OIDC_CLIENT_SECRET OAuth2 client secret for the Pocket ID application."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_client_secret"}}</div><div class="config-label-env">IDENTREE_OIDC_CLIENT_SECRET</div><div class="config-label-desc">OAuth2 client secret for the Pocket ID application.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
    {{/* PocketID API */}}
      <div class="config-section-row" data-section="pocketid"><span class="config-section-title">{{call .T "cfg_pocketid"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_POCKETID_API_KEY"}}<div class="config-table-row config-locked" data-section="pocketid" data-search="IDENTREE_POCKETID_API_KEY API key for Pocket ID management calls (user/group sync)."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_api_key"}}</div><div class="config-label-env">IDENTREE_POCKETID_API_KEY</div><div class="config-label-desc">API key for Pocket ID management calls (user/group sync).</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
      {{$v:=index .ConfigValues "IDENTREE_POCKETID_API_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_POCKETID_API_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="pocketid" data-search="IDENTREE_POCKETID_API_URL Internal URL of the Pocket ID API. Defaults to IDENTREE_OIDC_ISSUER_URL if blank."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_api_url"}}</div><div class="config-label-env">IDENTREE_POCKETID_API_URL</div><div class="config-label-desc">Internal URL of the Pocket ID API. Defaults to IDENTREE_OIDC_ISSUER_URL if blank.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_POCKETID_API_URL" value="{{$v}}" class="config-input" placeholder="defaults to OIDC issuer URL">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
    {{/* HTTP Server */}}
      <div class="config-section-row" data-section="server"><span class="config-section-title">{{call .T "cfg_server"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_LISTEN_ADDR"}}{{$lk:=index .ConfigLocked "IDENTREE_LISTEN_ADDR"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="server" data-search="IDENTREE_LISTEN_ADDR TCP address identree binds to. Defaults to :8090."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_listen_addr"}}</div><div class="config-label-env">IDENTREE_LISTEN_ADDR</div><div class="config-label-desc">TCP address identree binds to. Defaults to :8090.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LISTEN_ADDR" value="{{$v}}" class="config-input" placeholder=":8090">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_EXTERNAL_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_EXTERNAL_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="server" data-search="IDENTREE_EXTERNAL_URL Public-facing URL of identree, used in install scripts and approval emails."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_external_url"}}</div><div class="config-label-env">IDENTREE_EXTERNAL_URL</div><div class="config-label-desc">Public-facing URL of identree, used in install scripts and approval emails.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_EXTERNAL_URL" value="{{$v}}" class="config-input" placeholder="https://identree.example.com">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_INSTALL_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_INSTALL_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="server" data-search="IDENTREE_INSTALL_URL URL embedded in client install-script curl commands. Defaults to IDENTREE_EXTERNAL_URL."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_install_url"}}</div><div class="config-label-env">IDENTREE_INSTALL_URL</div><div class="config-label-desc">URL embedded in client install-script curl commands. Defaults to IDENTREE_EXTERNAL_URL.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_INSTALL_URL" value="{{$v}}" class="config-input" placeholder="defaults to external URL">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_SHARED_SECRET"}}<div class="config-table-row config-locked" data-section="server" data-search="IDENTREE_SHARED_SECRET HMAC secret shared with the client agent for install-time authentication."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_shared_secret"}}</div><div class="config-label-env">IDENTREE_SHARED_SECRET</div><div class="config-label-desc">HMAC secret shared with the client agent for install-time authentication.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
    {{/* Authentication */}}
      <div class="config-section-row" data-section="auth"><span class="config-section-title">{{call .T "cfg_auth"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_CHALLENGE_TTL"}}{{$lk:=index .ConfigLocked "IDENTREE_CHALLENGE_TTL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="auth" data-search="IDENTREE_CHALLENGE_TTL How long a WebAuthn challenge stays valid before expiring (e.g. 120s)."><div class="config-row-label"><div class="config-label-text">{{call .T "challenge_ttl"}}</div><div class="config-label-env">IDENTREE_CHALLENGE_TTL</div><div class="config-label-desc">How long a WebAuthn challenge stays valid before expiring (e.g. 120s).</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_CHALLENGE_TTL" value="{{$v}}" class="config-input" placeholder="120s">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_GRACE_PERIOD"}}{{$lk:=index .ConfigLocked "IDENTREE_GRACE_PERIOD"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="auth" data-search="IDENTREE_GRACE_PERIOD After a session expires, re-auth on the same host is auto-approved for this duration. 0s disables."><div class="config-row-label"><div class="config-label-text">{{call .T "grace_period"}}</div><div class="config-label-env">IDENTREE_GRACE_PERIOD</div><div class="config-label-desc">After a session expires, re-auth on the same host is auto-approved for this duration. 0s disables.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_GRACE_PERIOD" value="{{$v}}" class="config-input" placeholder="0s">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_ONE_TAP_MAX_AGE"}}{{$lk:=index .ConfigLocked "IDENTREE_ONE_TAP_MAX_AGE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="auth" data-search="IDENTREE_ONE_TAP_MAX_AGE Maximum Pocket ID session age for one-tap approval without full re-authentication."><div class="config-row-label"><div class="config-label-text">{{call .T "onetap_max_age"}}</div><div class="config-label-env">IDENTREE_ONE_TAP_MAX_AGE</div><div class="config-label-desc">Maximum Pocket ID session age for one-tap approval without full re-authentication.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ONE_TAP_MAX_AGE" value="{{$v}}" class="config-input" placeholder="24h">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
    {{/* LDAP */}}
      <div class="config-section-row" data-section="ldap"><span class="config-section-title">{{call .T "cfg_ldap"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_ENABLED"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_ENABLED"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_ENABLED Enable the built-in LDAP server for nsswitch and PAM integration."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_enabled"}}</div><div class="config-label-env">IDENTREE_LDAP_ENABLED</div><div class="config-label-desc">Enable the built-in LDAP server for nsswitch and PAM integration.</div></div><div class="config-row-control">{{if $lk}}<input type="checkbox" disabled {{if eq $v "true"}}checked{{end}}>{{else}}<input type="checkbox" name="IDENTREE_LDAP_ENABLED" value="true" {{if eq $v "true"}}checked{{end}}>{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_LISTEN_ADDR"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_LISTEN_ADDR"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_LISTEN_ADDR Address the LDAP server listens on. Use :389 or a non-privileged port like :3389."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_listen_addr"}}</div><div class="config-label-env">IDENTREE_LDAP_LISTEN_ADDR</div><div class="config-label-desc">Address the LDAP server listens on. Use :389 or a non-privileged port like :3389.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_LISTEN_ADDR" value="{{$v}}" class="config-input" placeholder=":3389">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_BASE_DN"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_BASE_DN"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_BASE_DN LDAP base DN for the directory tree."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_base_dn"}}</div><div class="config-label-env">IDENTREE_LDAP_BASE_DN</div><div class="config-label-desc">LDAP base DN for the directory tree.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_BASE_DN" value="{{$v}}" class="config-input" placeholder="dc=example,dc=com">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_BIND_DN"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_BIND_DN"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_BIND_DN Optional bind DN for read-only queries. Leave blank to allow anonymous binds."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_bind_dn"}}</div><div class="config-label-env">IDENTREE_LDAP_BIND_DN</div><div class="config-label-desc">Optional bind DN for read-only queries. Leave blank to allow anonymous binds.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_BIND_DN" value="{{$v}}" class="config-input" placeholder="optional">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_LDAP_BIND_PASSWORD"}}<div class="config-table-row config-locked" data-section="ldap" data-search="IDENTREE_LDAP_BIND_PASSWORD Password for the LDAP bind DN."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_bind_password"}}</div><div class="config-label-env">IDENTREE_LDAP_BIND_PASSWORD</div><div class="config-label-desc">Password for the LDAP bind DN.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_REFRESH_INTERVAL"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_REFRESH_INTERVAL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_REFRESH_INTERVAL How often identree re-syncs its user and group cache from Pocket ID."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_refresh_interval"}}</div><div class="config-label-env">IDENTREE_LDAP_REFRESH_INTERVAL</div><div class="config-label-desc">How often identree re-syncs its user and group cache from Pocket ID.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_REFRESH_INTERVAL" value="{{$v}}" class="config-input" placeholder="5m">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_UID_MAP_FILE"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_UID_MAP_FILE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_UID_MAP_FILE JSON file mapping usernames to stable POSIX UIDs. Auto-created on first use."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_uid_map_file"}}</div><div class="config-label-env">IDENTREE_LDAP_UID_MAP_FILE</div><div class="config-label-desc">JSON file mapping usernames to stable POSIX UIDs. Auto-created on first use.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_UID_MAP_FILE" value="{{$v}}" class="config-input" placeholder="/config/uidmap.json">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_SUDO_NO_AUTHENTICATE"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_SUDO_NO_AUTHENTICATE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_SUDO_NO_AUTHENTICATE PAM re-auth in sudo: false=always authenticate, true=never, claims=skip when OIDC groups grant sudo."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_sudo_no_auth"}}</div><div class="config-label-env">IDENTREE_LDAP_SUDO_NO_AUTHENTICATE</div><div class="config-label-desc">PAM re-auth in sudo: false=always authenticate, true=never, claims=skip when OIDC groups grant sudo.</div></div><div class="config-row-control">{{if $lk}}<select disabled class="config-select"><option>{{$v}}</option></select><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<select name="IDENTREE_LDAP_SUDO_NO_AUTHENTICATE" class="config-select"><option value="false" {{if eq $v "false"}}selected{{end}}>false</option><option value="true" {{if eq $v "true"}}selected{{end}}>true</option><option value="claims" {{if eq $v "claims"}}selected{{end}}>claims</option></select>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_SUDO_RULES_FILE"}}{{$lk:=index .ConfigLocked "IDENTREE_SUDO_RULES_FILE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_SUDO_RULES_FILE JSON file of static sudo rules applied in addition to group-based policy."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_sudo_rules_file"}}</div><div class="config-label-env">IDENTREE_SUDO_RULES_FILE</div><div class="config-label-desc">JSON file of static sudo rules applied in addition to group-based policy.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_SUDO_RULES_FILE" value="{{$v}}" class="config-input" placeholder="/config/sudorules.json">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_UID_BASE"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_UID_BASE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_UID_BASE Starting UID for dynamically assigned POSIX user IDs."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_uid_base"}}</div><div class="config-label-env">IDENTREE_LDAP_UID_BASE</div><div class="config-label-desc">Starting UID for dynamically assigned POSIX user IDs.</div></div><div class="config-row-control">{{if $lk}}<input type="number" value="{{$v}}" disabled class="config-input" style="max-width:120px"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="number" name="IDENTREE_LDAP_UID_BASE" value="{{$v}}" class="config-input" style="max-width:120px" min="0">{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_GID_BASE"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_GID_BASE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_GID_BASE Starting GID for dynamically assigned POSIX group IDs."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_gid_base"}}</div><div class="config-label-env">IDENTREE_LDAP_GID_BASE</div><div class="config-label-desc">Starting GID for dynamically assigned POSIX group IDs.</div></div><div class="config-row-control">{{if $lk}}<input type="number" value="{{$v}}" disabled class="config-input" style="max-width:120px"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="number" name="IDENTREE_LDAP_GID_BASE" value="{{$v}}" class="config-input" style="max-width:120px" min="0">{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_DEFAULT_SHELL"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_DEFAULT_SHELL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_DEFAULT_SHELL Login shell assigned when Pocket ID has no shell set for a user."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_default_shell"}}</div><div class="config-label-env">IDENTREE_LDAP_DEFAULT_SHELL</div><div class="config-label-desc">Login shell assigned when Pocket ID has no shell set for a user.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_DEFAULT_SHELL" value="{{$v}}" class="config-input" placeholder="/bin/bash">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_DEFAULT_HOME"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_DEFAULT_HOME"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_DEFAULT_HOME Home directory template. Use %s as a placeholder for the username."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_ldap_default_home"}}</div><div class="config-label-env">IDENTREE_LDAP_DEFAULT_HOME</div><div class="config-label-desc">Home directory template. Use %s as a placeholder for the username.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_DEFAULT_HOME" value="{{$v}}" class="config-input" placeholder="/home/%s">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_PROVISION_ENABLED"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_PROVISION_ENABLED"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_PROVISION_ENABLED Enable SSSD auto-provisioning via identree setup --sssd."><div class="config-row-label"><div class="config-label-text">SSSD auto-provision</div><div class="config-label-env">IDENTREE_LDAP_PROVISION_ENABLED</div><div class="config-label-desc">Enable /api/client/provision so identree setup --sssd can auto-configure SSSD on managed hosts.</div></div><div class="config-row-control">{{if $lk}}<input type="checkbox" disabled {{if eq $v "true"}}checked{{end}}>{{else}}<input type="checkbox" name="IDENTREE_LDAP_PROVISION_ENABLED" value="true" {{if eq $v "true"}}checked{{end}}>{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_EXTERNAL_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_EXTERNAL_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_EXTERNAL_URL LDAP URL returned to SSSD clients during auto-provisioning."><div class="config-row-label"><div class="config-label-text">LDAP external URL</div><div class="config-label-env">IDENTREE_LDAP_EXTERNAL_URL</div><div class="config-label-desc">LDAP URL returned to SSSD clients. Leave blank to auto-derive from IDENTREE_EXTERNAL_URL.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_LDAP_EXTERNAL_URL" value="{{$v}}" class="config-input" placeholder="ldap://identree.example.com:389">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_LDAP_TLS_CA_CERT"}}{{$lk:=index .ConfigLocked "IDENTREE_LDAP_TLS_CA_CERT"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="ldap" data-search="IDENTREE_LDAP_TLS_CA_CERT PEM CA certificate returned to SSSD clients for TLS verification."><div class="config-row-label"><div class="config-label-text">LDAP TLS CA cert</div><div class="config-label-env">IDENTREE_LDAP_TLS_CA_CERT</div><div class="config-label-desc">Optional PEM CA certificate included in provision responses so clients can verify LDAP TLS. Leave blank for plain LDAP.</div></div><div class="config-row-control">{{if $lk}}<textarea disabled class="config-input" rows="3" style="font-family:monospace;font-size:0.75rem">{{$v}}</textarea>{{else}}<textarea name="IDENTREE_LDAP_TLS_CA_CERT" class="config-input" rows="3" style="font-family:monospace;font-size:0.75rem" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----">{{$v}}</textarea>{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
    {{/* Admin Access */}}
      <div class="config-section-row" data-section="admin"><span class="config-section-title">{{call .T "cfg_admin_access"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_ADMIN_GROUPS"}}{{$lk:=index .ConfigLocked "IDENTREE_ADMIN_GROUPS"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="admin" data-search="IDENTREE_ADMIN_GROUPS Comma-separated Pocket ID group names whose members have admin access to this UI."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_admin_groups"}}</div><div class="config-label-env">IDENTREE_ADMIN_GROUPS</div><div class="config-label-desc">Comma-separated Pocket ID group names whose members have admin access to this UI.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ADMIN_GROUPS" value="{{$v}}" class="config-input" placeholder="admins, sudo-admins">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_ADMIN_APPROVAL_HOSTS"}}{{$lk:=index .ConfigLocked "IDENTREE_ADMIN_APPROVAL_HOSTS"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="admin" data-search="IDENTREE_ADMIN_APPROVAL_HOSTS Glob patterns for hosts that require admin approval before a user is granted access."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_admin_approval_hosts"}}</div><div class="config-label-env">IDENTREE_ADMIN_APPROVAL_HOSTS</div><div class="config-label-desc">Glob patterns for hosts that require admin approval before a user is granted access.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ADMIN_APPROVAL_HOSTS" value="{{$v}}" class="config-input" placeholder="prod-*, sensitive-host">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      <div class="config-table-row config-locked" data-section="admin" data-search="IDENTREE_API_KEYS bearer tokens management api"><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_api_keys"}}</div><div class="config-label-env">IDENTREE_API_KEYS</div><div class="config-label-desc">Bearer tokens for calling identree's management API. Set via environment variable only.</div></div><div class="config-row-control"><span style="font-size:0.875rem;color:var(--text-2)">{{.APIKeyCount}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
    {{/* Notifications */}}
      <div class="config-section-row" data-section="notifications"><span class="config-section-title">{{call .T "cfg_notifications"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_NOTIFY_BACKEND"}}{{$lk:=index .ConfigLocked "IDENTREE_NOTIFY_BACKEND"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="notifications" data-search="IDENTREE_NOTIFY_BACKEND Notification backend: ntfy, slack, discord, apprise, webhook, custom, or empty to disable."><div class="config-row-label"><div class="config-label-text">Backend</div><div class="config-label-env">IDENTREE_NOTIFY_BACKEND</div><div class="config-label-desc">Notification backend. Leave empty to disable notifications.</div></div><div class="config-row-control">{{if $lk}}<select disabled class="config-select"><option>{{$v}}</option></select><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<select name="IDENTREE_NOTIFY_BACKEND" id="notify-backend-select" class="config-select"><option value="" {{if eq $v ""}}selected{{end}}>— disabled —</option><option value="ntfy" {{if eq $v "ntfy"}}selected{{end}}>ntfy</option><option value="slack" {{if eq $v "slack"}}selected{{end}}>Slack</option><option value="discord" {{if eq $v "discord"}}selected{{end}}>Discord</option><option value="apprise" {{if eq $v "apprise"}}selected{{end}}>Apprise</option><option value="webhook" {{if eq $v "webhook"}}selected{{end}}>Webhook / raw JSON</option><option value="custom" {{if eq $v "custom"}}selected{{end}}>Custom command</option></select>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_NOTIFY_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_NOTIFY_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="notifications" data-notify-show="http" data-search="IDENTREE_NOTIFY_URL Webhook URL for the notification backend."><div class="config-row-label"><div class="config-label-text">URL</div><div class="config-label-env">IDENTREE_NOTIFY_URL</div><div class="config-label-desc">Webhook URL for the selected notification backend.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_NOTIFY_URL" value="{{$v}}" class="config-input" placeholder="https://ntfy.sh/my-topic">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_NOTIFY_TOKEN"}}<div class="config-table-row config-locked" data-section="notifications" data-search="IDENTREE_NOTIFY_TOKEN Optional Bearer token for the notification backend (e.g. ntfy auth)."><div class="config-row-label"><div class="config-label-text">Token</div><div class="config-label-env">IDENTREE_NOTIFY_TOKEN</div><div class="config-label-desc">Optional Bearer token for the notification backend (e.g. ntfy auth). Set via environment variable only.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
      {{$v:=index .ConfigValues "IDENTREE_NOTIFY_COMMAND"}}{{$lk:=index .ConfigLocked "IDENTREE_NOTIFY_COMMAND"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="notifications" data-notify-show="custom" data-search="IDENTREE_NOTIFY_COMMAND Path to a script or command invoked when backend is custom."><div class="config-row-label"><div class="config-label-text">Command</div><div class="config-label-env">IDENTREE_NOTIFY_COMMAND</div><div class="config-label-desc">Path to a script or command to execute (custom backend only).</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_NOTIFY_COMMAND" value="{{$v}}" class="config-input" placeholder="/usr/local/bin/notify.sh">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_NOTIFY_TIMEOUT"}}{{$lk:=index .ConfigLocked "IDENTREE_NOTIFY_TIMEOUT"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="notifications" data-search="IDENTREE_NOTIFY_TIMEOUT Timeout for notification HTTP requests and command execution."><div class="config-row-label"><div class="config-label-text">Timeout</div><div class="config-label-env">IDENTREE_NOTIFY_TIMEOUT</div><div class="config-label-desc">Timeout for notification HTTP requests and command execution (default 15s).</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input" style="max-width:120px">{{else}}<input type="text" name="IDENTREE_NOTIFY_TIMEOUT" value="{{$v}}" class="config-input" style="max-width:120px" placeholder="15s">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      <div class="config-table-row" data-section="notifications" data-notify-show="custom" style="display:none"><div class="config-row-label" style="grid-column:1/-1"><div class="config-info-block" style="margin:0"><p style="font-weight:600;margin-bottom:6px">Available NOTIFY_* environment variables</p><ul style="margin:0;padding-left:1.2em;font-size:0.875rem;line-height:1.7"><li><code>NOTIFY_USERNAME</code> — username requesting sudo</li><li><code>NOTIFY_HOSTNAME</code> — host the user is on</li><li><code>NOTIFY_USER_CODE</code> — 6-character verification code</li><li><code>NOTIFY_APPROVAL_URL</code> — URL to approve (uses one-tap if available)</li><li><code>NOTIFY_ONETAP_URL</code> — one-tap approval URL (may be empty)</li><li><code>NOTIFY_EXPIRES_IN</code> — seconds until the challenge expires</li><li><code>NOTIFY_TIMESTAMP</code> — ISO 8601 timestamp</li></ul></div></div></div>
    {{/* Break-glass Escrow */}}
      <div class="config-section-row" data-section="escrow"><span class="config-section-title">{{call .T "cfg_escrow"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_ESCROW_BACKEND"}}{{$lk:=index .ConfigLocked "IDENTREE_ESCROW_BACKEND"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="escrow" data-search="IDENTREE_ESCROW_BACKEND Backend used to store break-glass passwords. local encrypts them in identree's own state file."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_backend"}}</div><div class="config-label-env">IDENTREE_ESCROW_BACKEND</div><div class="config-label-desc">Backend used to store break-glass passwords. local encrypts them in identree's own state file.</div></div><div class="config-row-control">{{if $lk}}<select disabled class="config-select"><option>{{$v}}</option></select><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<select name="IDENTREE_ESCROW_BACKEND" class="config-select"><option value="" {{if eq $v ""}}selected{{end}}>— none —</option><option value="1password-connect" {{if eq $v "1password-connect"}}selected{{end}}>1Password Connect</option><option value="vault" {{if eq $v "vault"}}selected{{end}}>HashiCorp Vault</option><option value="bitwarden" {{if eq $v "bitwarden"}}selected{{end}}>Bitwarden SM</option><option value="infisical" {{if eq $v "infisical"}}selected{{end}}>Infisical</option><option value="local" {{if eq $v "local"}}selected{{end}}>Local (AES-256-GCM)</option></select>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_ESCROW_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_ESCROW_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="escrow" data-search="IDENTREE_ESCROW_URL API URL of the external secret backend (Vault, 1Password Connect, etc.)."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_url"}}</div><div class="config-label-env">IDENTREE_ESCROW_URL</div><div class="config-label-desc">API URL of the external secret backend (Vault, 1Password Connect, etc.).</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ESCROW_URL" value="{{$v}}" class="config-input" placeholder="https://vault.example.com">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_ESCROW_AUTH_ID"}}{{$lk:=index .ConfigLocked "IDENTREE_ESCROW_AUTH_ID"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="escrow" data-search="IDENTREE_ESCROW_AUTH_ID Application or client ID for authenticating to the secret backend."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_auth_id"}}</div><div class="config-label-env">IDENTREE_ESCROW_AUTH_ID</div><div class="config-label-desc">Application or client ID for authenticating to the secret backend.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ESCROW_AUTH_ID" value="{{$v}}" class="config-input">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_ESCROW_AUTH_SECRET"}}<div class="config-table-row config-locked" data-section="escrow" data-search="IDENTREE_ESCROW_AUTH_SECRET Credential for the secret backend."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_auth_secret"}}</div><div class="config-label-env">IDENTREE_ESCROW_AUTH_SECRET</div><div class="config-label-desc">Credential for the secret backend.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_ESCROW_ENCRYPTION_KEY"}}<div class="config-table-row config-locked" data-section="escrow" data-search="IDENTREE_ESCROW_ENCRYPTION_KEY Encryption key for the local backend (AES-256-GCM). Required when backend=local."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_encryption_key"}}</div><div class="config-label-env">IDENTREE_ESCROW_ENCRYPTION_KEY</div><div class="config-label-desc">Encryption key for the local backend (AES-256-GCM). Required when backend=local.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">required for local backend</span></div></div>
      {{$v:=index .ConfigValues "IDENTREE_ESCROW_PATH"}}{{$lk:=index .ConfigLocked "IDENTREE_ESCROW_PATH"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="escrow" data-search="IDENTREE_ESCROW_PATH Storage path or prefix in the secret backend (Vault mount/path, 1Password vault name, etc.)."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_path"}}</div><div class="config-label-env">IDENTREE_ESCROW_PATH</div><div class="config-label-desc">Storage path or prefix in the secret backend (Vault mount/path, 1Password vault name, etc.).</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ESCROW_PATH" value="{{$v}}" class="config-input" placeholder="secret/identree/breakglass">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_ESCROW_WEB_URL"}}{{$lk:=index .ConfigLocked "IDENTREE_ESCROW_WEB_URL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="escrow" data-search="IDENTREE_ESCROW_WEB_URL Optional link to the backend web UI, shown in the admin panel."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_escrow_web_url"}}</div><div class="config-label-env">IDENTREE_ESCROW_WEB_URL</div><div class="config-label-desc">Optional link to the backend web UI, shown in the admin panel.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_ESCROW_WEB_URL" value="{{$v}}" class="config-input" placeholder="https://my.1password.com/app#/...">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
    {{/* Client Defaults */}}
      <div class="config-section-row" data-section="client"><span class="config-section-title">{{call .T "cfg_client_defaults"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"}}{{$lk:=index .ConfigLocked "IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="client" data-search="IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE Default break-glass password style. Client agents can override this per host."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_breakglass_type"}}</div><div class="config-label-env">IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE</div><div class="config-label-desc">Default break-glass password style. Client agents can override this per host.</div></div><div class="config-row-control">{{if $lk}}<select disabled class="config-select"><option>{{$v}}</option></select><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<select name="IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE" class="config-select"><option value="" {{if eq $v ""}}selected{{end}}>— default —</option><option value="random" {{if eq $v "random"}}selected{{end}}>random</option><option value="passphrase" {{if eq $v "passphrase"}}selected{{end}}>passphrase</option><option value="alphanumeric" {{if eq $v "alphanumeric"}}selected{{end}}>alphanumeric</option></select>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS"}}{{$lk:=index .ConfigLocked "IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="client" data-search="IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS Default days before break-glass passwords auto-rotate. 0 disables automatic rotation."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_breakglass_days"}}</div><div class="config-label-env">IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS</div><div class="config-label-desc">Default days before break-glass passwords auto-rotate. 0 disables automatic rotation.</div></div><div class="config-row-control">{{if $lk}}<input type="number" value="{{$v}}" disabled class="config-input" style="max-width:120px"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="number" name="IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS" value="{{$v}}" class="config-input" style="max-width:120px" min="0" placeholder="90">{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"}}{{$lk:=index .ConfigLocked "IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="client" data-search="IDENTREE_CLIENT_TOKEN_CACHE_ENABLED Allow client agents to cache OIDC tokens locally, reducing Pocket ID roundtrips."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_token_cache"}}</div><div class="config-label-env">IDENTREE_CLIENT_TOKEN_CACHE_ENABLED</div><div class="config-label-desc">Allow client agents to cache OIDC tokens locally, reducing Pocket ID roundtrips.</div></div><div class="config-row-control">{{if $lk}}<input type="checkbox" disabled {{if eq $v "true"}}checked{{end}}>{{else}}<input type="checkbox" name="IDENTREE_CLIENT_TOKEN_CACHE_ENABLED" value="true" {{if eq $v "true"}}checked{{end}}>{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>

      {{$v:=index .ConfigValues "IDENTREE_CLIENT_POLL_INTERVAL"}}{{$lk:=index .ConfigLocked "IDENTREE_CLIENT_POLL_INTERVAL"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="client" data-search="IDENTREE_CLIENT_POLL_INTERVAL How often clients poll for challenge resolution. Pushed to clients at every auth."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_client_poll_interval"}}</div><div class="config-label-env">IDENTREE_CLIENT_POLL_INTERVAL</div><div class="config-label-desc">How often clients poll for challenge resolution. Pushed to clients at every auth.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input" style="max-width:120px"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="text" name="IDENTREE_CLIENT_POLL_INTERVAL" value="{{$v}}" class="config-input" style="max-width:120px" placeholder="2s">{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_CLIENT_TIMEOUT"}}{{$lk:=index .ConfigLocked "IDENTREE_CLIENT_TIMEOUT"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="client" data-search="IDENTREE_CLIENT_TIMEOUT Max time to wait for user approval. Pushed to clients at every auth."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_client_timeout"}}</div><div class="config-label-env">IDENTREE_CLIENT_TIMEOUT</div><div class="config-label-desc">Max time to wait for user approval. Pushed to clients at every auth.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input" style="max-width:120px"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="text" name="IDENTREE_CLIENT_TIMEOUT" value="{{$v}}" class="config-input" style="max-width:120px" placeholder="120s">{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_CLIENT_BREAKGLASS_ENABLED"}}{{$lk:=index .ConfigLocked "IDENTREE_CLIENT_BREAKGLASS_ENABLED"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="client" data-search="IDENTREE_CLIENT_BREAKGLASS_ENABLED Enable break-glass fallback on clients. Pushed to clients at every auth."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_client_breakglass_enabled"}}</div><div class="config-label-env">IDENTREE_CLIENT_BREAKGLASS_ENABLED</div><div class="config-label-desc">Enable break-glass fallback on clients. Pushed to clients at every auth.</div></div><div class="config-row-control">{{if $lk}}<input type="checkbox" disabled {{if eq $v "true"}}checked{{end}}><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="checkbox" name="IDENTREE_CLIENT_BREAKGLASS_ENABLED" value="true" {{if eq $v "true"}}checked{{end}}>{{end}}</div></div>
    {{/* Miscellaneous */}}
      <div class="config-section-row" data-section="misc"><span class="config-section-title">{{call .T "cfg_misc"}}</span><button type="submit" class="saction-btn saction-primary config-save-btn">{{call .T "save"}}</button></div>
      {{$v:=index .ConfigValues "IDENTREE_HOST_REGISTRY_FILE"}}{{$lk:=index .ConfigLocked "IDENTREE_HOST_REGISTRY_FILE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="misc" data-search="IDENTREE_HOST_REGISTRY_FILE JSON file listing registered hosts and their metadata."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_host_registry_file"}}</div><div class="config-label-env">IDENTREE_HOST_REGISTRY_FILE</div><div class="config-label-desc">JSON file listing registered hosts and their metadata.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_HOST_REGISTRY_FILE" value="{{$v}}" class="config-input" placeholder="/config/hosts.json">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_DEFAULT_PAGE_SIZE"}}{{$lk:=index .ConfigLocked "IDENTREE_DEFAULT_PAGE_SIZE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="misc" data-search="IDENTREE_DEFAULT_PAGE_SIZE Number of entries shown per page in the history view."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_history_page_size"}}</div><div class="config-label-env">IDENTREE_DEFAULT_PAGE_SIZE</div><div class="config-label-desc">Number of entries shown per page in the history view.</div></div><div class="config-row-control">{{if $lk}}<input type="number" value="{{$v}}" disabled class="config-input" style="max-width:120px"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{else}}<input type="number" name="IDENTREE_DEFAULT_PAGE_SIZE" value="{{$v}}" class="config-input" style="max-width:120px" min="0" max="200" placeholder="10">{{end}}</div></div>
      {{$v:=index .ConfigValues "IDENTREE_SESSION_STATE_FILE"}}{{$lk:=index .ConfigLocked "IDENTREE_SESSION_STATE_FILE"}}<div class="config-table-row{{if $lk}} config-locked{{end}}" data-section="misc" data-search="IDENTREE_SESSION_STATE_FILE JSON file for persisting sessions, grace periods, and the action log."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_session_state_file"}}</div><div class="config-label-env">IDENTREE_SESSION_STATE_FILE</div><div class="config-label-desc">JSON file for persisting sessions, grace periods, and the action log.</div></div><div class="config-row-control">{{if $lk}}<input type="text" value="{{$v}}" disabled class="config-input">{{else}}<input type="text" name="IDENTREE_SESSION_STATE_FILE" value="{{$v}}" class="config-input" placeholder="/config/sessions.json">{{end}}{{if $lk}}<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}</div></div>
      {{$sc:=index .ConfigSecrets "IDENTREE_WEBHOOK_SECRET"}}<div class="config-table-row config-locked" data-section="misc" data-search="IDENTREE_WEBHOOK_SECRET HMAC secret for verifying Pocket ID webhook payloads."><div class="config-row-label"><div class="config-label-text">{{call .T "cfg_webhook_secret"}}</div><div class="config-label-env">IDENTREE_WEBHOOK_SECRET</div><div class="config-label-desc">HMAC secret for verifying Pocket ID webhook payloads.</div></div><div class="config-row-control"><span class="config-secret-badge{{if $sc}} configured{{end}}">{{if $sc}}{{call .T "configured"}}{{else}}{{call .T "not_configured"}}{{end}}</span><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-3);flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span style="font-size:0.75rem;color:var(--text-3)">env only</span></div></div>
    </div>
    </form>

    {{/* ── Install command card ────────────────────────────────────────── */}}
    <div class="config-table" style="margin-top:16px">
      <div class="config-filter-header" style="cursor:default">
        <span class="config-section-title">Install command</span>
      </div>
      <div style="padding:12px 16px;display:flex;flex-direction:column;gap:10px">
        <p style="margin:0;font-size:0.8125rem;color:var(--text-2)">Run this on a managed host to install identree and configure PAM. Pass <code>SETUP_SSSD=1</code> to also configure SSSD for LDAP identity lookup.</p>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <label style="font-size:0.8125rem;font-weight:500;white-space:nowrap">Mode:</label>
          <label style="font-size:0.8125rem;display:flex;align-items:center;gap:4px"><input type="radio" name="install-mode" value="pam" checked> PAM only</label>
          <label style="font-size:0.8125rem;display:flex;align-items:center;gap:4px"><input type="radio" name="install-mode" value="sssd"> PAM + SSSD{{if not .LDAPProvisionEnabled}} <span style="font-size:0.75rem;color:var(--text-3)">(requires IDENTREE_LDAP_PROVISION_ENABLED=true)</span>{{end}}</label>
        </div>
        <div style="position:relative">
          <code id="install-cmd-text" style="display:block;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 40px 10px 10px;font-size:0.8rem;word-break:break-all;color:var(--text)">SHARED_SECRET=<span id="install-secret-placeholder">YOUR_SHARED_SECRET</span> curl -fsSL {{.InstallURL}}/install.sh | sudo bash</code>
          <button type="button" id="install-cmd-copy" style="position:absolute;top:6px;right:6px;background:none;border:none;cursor:pointer;padding:4px;color:var(--text-2)" title="Copy"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        </div>
        {{if .SharedSecretConfigured}}<p style="margin:0;font-size:0.75rem;color:var(--text-3)">IDENTREE_SHARED_SECRET is configured. Replace <code>YOUR_SHARED_SECRET</code> with the actual value from your server config.</p>{{else}}<p style="margin:0;font-size:0.75rem;color:var(--danger)">IDENTREE_SHARED_SECRET is not configured — clients cannot authenticate.</p>{{end}}
      </div>
    </div>

    <script nonce="{{.CSPNonce}}">
    (function(){
      var installURL="{{.InstallURL}}";
      function updateInstallCmd(){
        var sssd=document.querySelector('input[name="install-mode"][value="sssd"]');
        var base='SHARED_SECRET=YOUR_SHARED_SECRET curl -fsSL '+installURL+'/install.sh | sudo bash';
        var cmd=sssd&&sssd.checked?'SHARED_SECRET=YOUR_SHARED_SECRET SETUP_SSSD=1 curl -fsSL '+installURL+'/install.sh | sudo bash':base;
        var el=document.getElementById('install-cmd-text');
        if(el)el.textContent=cmd;
      }
      document.querySelectorAll('input[name="install-mode"]').forEach(function(r){r.addEventListener('change',updateInstallCmd);});
      var copyBtn=document.getElementById('install-cmd-copy');
      if(copyBtn)copyBtn.addEventListener('click',function(){
        var el=document.getElementById('install-cmd-text');
        if(el&&navigator.clipboard)navigator.clipboard.writeText(el.textContent);
      });
    })();
    </script>

    <script nonce="{{.CSPNonce}}">
    (function(){
      /* ── Filter ─────────────────────────────────────────────────────── */
      var ft=document.getElementById('config-filter-toggle');
      var fr=document.getElementById('config-filter-row');
      var fi=document.getElementById('config-filter-input');
      var fc=document.getElementById('config-filter-clear');
      if(ft&&fr)ft.addEventListener('click',function(){
        var shown=fr.style.display!=='none';
        fr.style.display=shown?'none':'';
        ft.classList.toggle('active',!shown);
        if(!shown&&fi)fi.focus();
      });
      function filterConfig(){
        var q=fi?fi.value.toLowerCase():'';
        document.querySelectorAll('#config-table .config-table-row').forEach(function(r){r.classList.toggle('cfg-hidden',q!==''&&(r.dataset.search||'').toLowerCase().indexOf(q)===-1);});
        document.querySelectorAll('#config-table .config-section-row').forEach(function(s){
          var sec=s.dataset.section;
          var rows=document.querySelectorAll('#config-table .config-table-row[data-section="'+sec+'"]');
          s.style.display=(!q||Array.from(rows).some(function(r){return!r.classList.contains('cfg-hidden');}))?'':'none';
        });
      }
      if(fi)fi.addEventListener('input',filterConfig);
      if(fc)fc.addEventListener('click',function(){if(fi)fi.value='';filterConfig();});

      /* ── Unsaved-changes tracking ────────────────────────────────────── */
      var initialValues={};
      var dirtySections={};
      var submitted=false;
      // Snapshot initial values of all editable inputs.
      document.querySelectorAll('#config-table .config-input, #config-table input[type="checkbox"]').forEach(function(inp){
        var key=inp.name||inp.id;
        if(!key)return;
        initialValues[key]=inp.type==='checkbox'?inp.checked:inp.value;
      });
      function getSectionRow(sec){return document.querySelector('#config-table .config-section-row[data-section="'+sec+'"]');}
      function updateDirty(inp){
        var row=inp.closest('.config-table-row');
        if(!row)return;
        var sec=row.dataset.section;
        if(!sec)return;
        var key=inp.name||inp.id;
        var cur=inp.type==='checkbox'?inp.checked:inp.value;
        var dirty=String(cur)!==String(initialValues[key]!==undefined?initialValues[key]:'');
        if(dirty){dirtySections[sec]=true;}else{
          // Re-check all inputs in this section.
          var stillDirty=false;
          document.querySelectorAll('#config-table .config-table-row[data-section="'+sec+'"] .config-input, #config-table .config-table-row[data-section="'+sec+'"] input[type="checkbox"]').forEach(function(i){
            var k=i.name||i.id;
            var v=i.type==='checkbox'?i.checked:i.value;
            if(String(v)!==String(initialValues[k]!==undefined?initialValues[k]:''))stillDirty=true;
          });
          if(!stillDirty)delete dirtySections[sec];
        }
        var sr=getSectionRow(sec);
        if(sr)sr.classList.toggle('config-section-dirty',!!dirtySections[sec]);
      }
      document.querySelectorAll('#config-table .config-input').forEach(function(inp){
        inp.addEventListener('input',function(){updateDirty(inp);});
      });
      document.querySelectorAll('#config-table input[type="checkbox"]').forEach(function(inp){
        inp.addEventListener('change',function(){updateDirty(inp);});
      });
      // Clear dirty state on form submit.
      var form=document.querySelector('form[action="/admin/config"]');
      if(form)form.addEventListener('submit',function(){submitted=true;});

      /* ── Prevent double-submission ───────────────────────────────────── */
      (function(){
        var configForm=document.querySelector('form[action="/admin/config"]');
        if(!configForm)return;
        // Intercept click on each save button and POST via fetch for proper error handling
        configForm.querySelectorAll('.config-save-btn').forEach(function(btn){
          btn.addEventListener('click',function(e){
            e.preventDefault();
            var origText=btn.textContent;
            btn.disabled=true;
            btn.textContent='Saving\u2026';
            submitted=true;
            var body=new URLSearchParams(new FormData(configForm));
            fetch('/admin/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
              .then(function(r){
                if(r.status===401){window.location.href='/login';return;}
                if(!r.ok){return r.text().then(function(t){throw new Error(t||r.statusText);});}
                window.location.reload();
              })
              .catch(function(err){
                btn.disabled=false;
                btn.textContent=origText;
                submitted=false;
                var errDiv=document.createElement('div');
                errDiv.className='banner banner-error';
                errDiv.setAttribute('role','alert');
                errDiv.textContent='Save failed: '+(err&&err.message?err.message:'Network error');
                var main=document.getElementById('main-content')||document.body;
                main.insertBefore(errDiv,main.firstChild);
                setTimeout(function(){errDiv.remove();},6000);
              });
          });
        });
      })();

      /* ── Nav interception ────────────────────────────────────────────── */
      function dirtyNames(){
        var sectionLabels={'oidc':'OIDC Authentication','pocketid':'PocketID API','server':'Server','auth':'Authentication','ldap':'LDAP','admin':'Admin Access','notifications':'Notifications','escrow':'Break-Glass Escrow','client_defaults':'Client Defaults','misc':'Miscellaneous'};
        return Object.keys(dirtySections).map(function(s){return sectionLabels[s]||s;});
      }
      document.querySelectorAll('.nav-item, .sidebar-sub a').forEach(function(link){
        link.addEventListener('click',function(e){
          if(submitted||Object.keys(dirtySections).length===0)return;
          e.preventDefault();
          var href=link.href;
          var names=dirtyNames();
          if(window.confirm('You have unsaved changes in:\n  • '+names.join('\n  • ')+'\n\nLeave without saving?')){
            submitted=true;
            window.location.href=href;
          }
        });
      });
      window.addEventListener('beforeunload',function(e){
        if(!submitted&&Object.keys(dirtySections).length>0){e.preventDefault();return e.returnValue='';}
      });

      /* ── Notify backend show/hide ────────────────────────────────────── */
      (function(){
        var sel=document.getElementById('notify-backend-select');
        if(!sel)return;
        function applyNotifyVisibility(){
          var v=sel.value;
          document.querySelectorAll('[data-notify-show]').forEach(function(row){
            var show=row.getAttribute('data-notify-show');
            if(show==='http'){
              row.style.display=(v!==''&&v!=='custom')?'':'none';
            } else if(show==='custom'){
              row.style.display=(v==='custom')?'':'none';
            }
          });
        }
        sel.addEventListener('change',applyNotifyVisibility);
        applyNotifyVisibility();
      })();

      /* ── Restart button ──────────────────────────────────────────────── */
      var restartBtn=document.getElementById('restart-server-btn');
      if(restartBtn){
        restartBtn.addEventListener('click',function(){
          if(!window.confirm('Restart the server now? You will be briefly disconnected.'))return;
          restartBtn.disabled=true;restartBtn.textContent='Restarting…';
          var form=document.querySelector('form[action="/admin/config"]');
          var body=new URLSearchParams();
          if(form){
            var u=form.querySelector('[name=username]'),ct=form.querySelector('[name=csrf_token]'),ts=form.querySelector('[name=csrf_ts]');
            if(u)body.set('username',u.value);
            if(ct)body.set('csrf_token',ct.value);
            if(ts)body.set('csrf_ts',ts.value);
          }
          fetch('/api/admin/restart',{method:'POST',body:body,headers:{'Content-Type':'application/x-www-form-urlencoded'}}).catch(function(){});
          setTimeout(function(){window.location.reload();},3000);
        });
      }
    })();
    </script>


    {{else if eq .AdminTab "users"}}
    {{if .Users}}
    <div class="users-table" id="users-table" role="table" aria-label="{{call .T "users"}}">
      <div class="users-table-header" role="row">
        <div class="gtcol gtcol-uname" role="columnheader" style="gap:8px;align-items:center">
          <button type="button" class="filter-toggle-btn" id="users-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button>
          <a href="/admin/users?sort=name&dir={{if and (eq .UserSort "name") (eq .UserDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .UserSort "name"}} active{{end}}">{{call .T "user"}}{{if eq .UserSort "name"}} {{if eq .UserDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
        </div>
        <div class="gtcol gtcol-ugroups" role="columnheader"><span class="col-sort-link">{{call .T "groups"}}</span></div>
        <div class="gtcol gtcol-uactions" role="columnheader"><span class="col-sort-link">{{call .T "action"}}</span></div>
      </div>
      <div class="users-table-filter" id="users-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="uname" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="ugroups" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div style="display:flex;justify-content:flex-end;align-items:center;padding:0 6px"><button type="button" class="filter-clear-btn" id="users-clear">{{call .T "clear_filter"}}</button></div>
      </div>
      {{range .Users}}
      <div class="users-table-row" role="row">
        <div class="gtcol gtcol-uname" role="cell"><a href="/access?user={{.Username}}" class="pill user">{{.Username}}</a></div>
        <div class="gtcol gtcol-ugroups" role="cell">
          <div class="pill-cell">{{if .Groups}}{{range .Groups}}<a href="/admin/groups#group-{{.Name}}" class="group-badge group-badge-link">{{.Name}}</a>{{end}}{{end}}</div>
        </div>
        <div class="gtcol gtcol-uactions" role="cell" style="gap:6px;flex-wrap:nowrap;align-items:center;justify-content:flex-end;">
          {{if gt .ActiveSessions 0}}<a href="/?user={{.Username}}" class="saction-btn saction-sessions saction-primary"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>{{call $.T "sessions"}} ({{.ActiveSessions}})</a>{{end}}
          <a href="/access?user={{.Username}}" class="saction-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>{{call $.T "access"}}</a>
          <a href="/history?user={{.Username}}" class="saction-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call $.T "history"}}</a>
          <form method="POST" action="/api/users/remove" style="display:inline">
            <input type="hidden" name="target_user" value="{{.Username}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="saction-btn saction-danger confirm-submit" data-confirm="{{call $.T "confirm_remove_user"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>{{call $.T "remove_user"}}</button>
          </form>
          {{if .UserID}}<button type="button" class="saction-btn ssh-keys-toggle" data-claims-target="uclaims-{{.UserID}}" data-user-id="{{.UserID}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>Claims <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px"><polyline points="6 9 12 15 18 9"/></svg></button>{{end}}
        </div>
      </div>
      {{if .UserID}}
      <div class="user-claims-panel" id="uclaims-{{.UserID}}" data-user-id="{{.UserID}}" data-username="{{.Username}}">
        <div class="claims-panel-title">User Claims — {{.Username}}</div>
        <form method="POST" action="/api/admin/users/claims" class="ssh-keys-form">
          <input type="hidden" name="user_id" value="{{.UserID}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <div class="claims-form" style="margin-bottom:14px">
            <span class="claims-form-label">loginShell</span>
            <div class="claims-form-field"><input type="text" name="loginShell" value="{{.LoginShell}}" placeholder="/bin/bash"><span class="claims-form-hint">Login shell assigned via LDAP. e.g. /bin/bash, /bin/zsh</span></div>
            <span class="claims-form-label">homeDirectory</span>
            <div class="claims-form-field"><input type="text" name="homeDirectory" value="{{.HomeDirectory}}" placeholder="/home/username"><span class="claims-form-hint">Home directory path assigned via LDAP.</span></div>
          </div>
          <div style="font-size:0.75rem;font-weight:600;color:var(--text-3);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:8px">SSH Public Keys</div>
          <div class="ssh-keys-list" id="ssh-list-{{.UserID}}">
            {{if .SSHKeys}}
            {{range .SSHKeys}}<div class="ssh-key-row"><textarea name="ssh_keys" rows="2">{{.}}</textarea><button type="button" class="ssh-key-remove" title="Remove">✕</button></div>{{end}}
            {{else}}<div class="ssh-keys-empty" id="ssh-empty-{{.UserID}}">No SSH keys configured.</div>{{end}}
          </div>
          <div style="display:flex;gap:8px;align-items:center;margin-top:6px">
            <button type="button" class="saction-btn ssh-key-add" data-list="ssh-list-{{.UserID}}" data-empty="ssh-empty-{{.UserID}}">+ Add Key</button>
            <button type="submit" class="saction-btn">Save</button>
            <button type="button" class="saction-btn claims-panel-cancel" data-claims-target="uclaims-{{.UserID}}">Cancel</button>
          </div>
          {{if .OtherClaims}}
          <div class="claims-readonly">
            <div style="font-size:0.75rem;font-weight:600;color:var(--text-3);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:6px">Read-only claims (not managed by identree)</div>
            {{range .OtherClaims}}<div class="claims-readonly-row"><span class="claims-readonly-key">{{.Key}}</span><span class="claims-readonly-val">{{.Value}}</span></div>{{end}}
          </div>
          {{end}}
        </form>
      </div>
      {{end}}
      {{end}}
    </div>
    <div class="pagination-bar" id="users-pagination"></div>
    <div id="users-filter-empty-msg" style="display:none" class="empty-state">No results match your filter</div>
    <script nonce="{{.CSPNonce}}">
    (function(){
      var usersPage=1,usersPs={{.DefaultPageSize}};
      function hideRowAndPanel(r){r.style.display='none';var p=r.nextElementSibling;if(p&&p.classList.contains('user-claims-panel')){p.style.display='none';}}
      function renderUsersPager(vis){
        var bar=document.getElementById('users-pagination');
        if(!bar)return;
        var total=vis.length,totalPages=Math.max(1,Math.ceil(total/usersPs));
        if(usersPage>totalPages)usersPage=1;
        var start=(usersPage-1)*usersPs;
        var allRows=Array.from(document.querySelectorAll('#users-table .users-table-row'));
        allRows.forEach(function(r){hideRowAndPanel(r);});
        vis.slice(start,start+usersPs).forEach(function(r){r.style.display='';});
        var emptyMsg=document.getElementById('users-filter-empty-msg');
        if(emptyMsg){emptyMsg.style.display=total===0?'':'none';}
        if(totalPages<=1&&total>0){bar.innerHTML='';vis.forEach(function(r){r.style.display='';});return;}
        if(total===0){bar.innerHTML='';return;}
        bar.innerHTML='<button class="pagination-btn" '+(usersPage<=1?'disabled':'')+'>&#8592;</button><span class="pagination-info">'+(start+1)+'&#8211;'+Math.min(start+usersPs,total)+' of '+total+'</span><button class="pagination-btn" '+(usersPage>=totalPages?'disabled':'')+'>&#8594;</button><select class="pagination-size-select">'+[15,30,50,100].map(function(n){return'<option value="'+n+'"'+(n===usersPs?' selected':'')+'>'+n+' per page</option>';}).join('')+'</select>';
        var btns=bar.querySelectorAll('.pagination-btn');
        if(!btns[0].disabled)btns[0].addEventListener('click',function(){usersPage--;filterUsers();});
        if(!btns[1].disabled)btns[1].addEventListener('click',function(){usersPage++;filterUsers();});
        bar.querySelector('.pagination-size-select').addEventListener('change',function(){usersPs=parseInt(this.value);usersPage=1;filterUsers();});
      }
      function filterUsers(){
        var filters={};
        document.querySelectorAll('#users-table .gtcol-filter-input').forEach(function(inp){ filters[inp.dataset.col]=inp.value.toLowerCase().trim(); });
        var allRows=Array.from(document.querySelectorAll('#users-table .users-table-row'));
        var vis=allRows.filter(function(row){
          for(var col in filters){ if(!filters[col]) continue; var cell=row.querySelector('.gtcol-'+col); if(cell&&cell.textContent.toLowerCase().indexOf(filters[col])===-1){return false;} }
          return true;
        });
        renderUsersPager(vis);
      }
      document.querySelectorAll('#users-table .gtcol-filter-input').forEach(function(inp){ inp.addEventListener('input',function(){usersPage=1;filterUsers();}); });
      var uc=document.getElementById('users-clear');
      if(uc)uc.addEventListener('click',function(){document.querySelectorAll('#users-table .gtcol-filter-input').forEach(function(i){i.value='';});usersPage=1;filterUsers();});
      (function(){var ftb=document.getElementById('users-filter-toggle');var ftr=document.getElementById('users-filter-row');if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      document.querySelectorAll('.confirm-submit').forEach(function(btn){
        btn.addEventListener('click',function(e){ if(!confirm(btn.dataset.confirm)){ e.preventDefault(); } });
      });
      // SSH Keys panel toggle
      document.querySelectorAll('.ssh-keys-toggle').forEach(function(btn){
        btn.addEventListener('click',function(){
          var id=btn.dataset.claimsTarget;
          var panel=document.getElementById(id);
          if(!panel)return;
          var open=panel.style.display==='block';
          panel.style.display=open?'none':'block';
          var chevron=btn.querySelector('svg:last-child');
          if(chevron){chevron.style.transform=open?'':'rotate(180deg)';}
        });
      });
      // SSH key add/remove
      function addKeyRow(list,emptyEl){
        if(emptyEl){emptyEl.style.display='none';}
        var row=document.createElement('div');row.className='ssh-key-row';
        var ta=document.createElement('textarea');ta.name='ssh_keys';ta.rows=2;ta.placeholder='ssh-ed25519 AAAA…';
        var rm=document.createElement('button');rm.type='button';rm.className='ssh-key-remove';rm.title='Remove';rm.textContent='✕';
        rm.addEventListener('click',function(){row.remove();if(!list.querySelector('.ssh-key-row')&&emptyEl){emptyEl.style.display='';}});
        row.appendChild(ta);row.appendChild(rm);list.appendChild(row);ta.focus();
      }
      document.querySelectorAll('.ssh-key-add').forEach(function(btn){
        btn.addEventListener('click',function(){
          var list=document.getElementById(btn.dataset.list);
          var emptyEl=document.getElementById(btn.dataset.empty);
          if(list)addKeyRow(list,emptyEl);
        });
      });
      document.querySelectorAll('.ssh-key-remove').forEach(function(btn){
        btn.addEventListener('click',function(){
          var row=btn.closest('.ssh-key-row');
          var list=row&&row.parentElement;
          row&&row.remove();
          if(list&&!list.querySelector('.ssh-key-row')){var em=document.getElementById(list.id.replace('ssh-list-','ssh-empty-'));if(em)em.style.display='';}
        });
      });
      // Claims cancel buttons
      document.querySelectorAll('.claims-panel-cancel').forEach(function(btn){
        btn.addEventListener('click',function(){
          var id=btn.dataset.claimsTarget;
          var panel=document.getElementById(id);
          if(panel){panel.style.display='none';}
          var toggle=document.querySelector('[data-claims-target="'+id+'"]');
          if(toggle){var chevron=toggle.querySelector('svg:last-child');if(chevron){chevron.style.transform='';}}
        });
      });
      // Submit claims forms via fetch to keep panel open
      document.querySelectorAll('.ssh-keys-form').forEach(function(form){
        form.addEventListener('submit',function(e){
          e.preventDefault();
          var saveBtn=form.querySelector('button[type=submit]');
          if(saveBtn)saveBtn.disabled=true;
          fetch(form.action,{method:'POST',headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(form))})
            .then(function(r){if(r.status===401){window.location.href='/login';return;}return r.ok?r.json():r.text().then(function(t){throw new Error(t);});})
            .then(function(){
              var ok=document.createElement('span');
              ok.textContent=' ✓ Saved';ok.style.cssText='color:var(--success);font-size:0.8125rem;font-weight:600';
              if(saveBtn){saveBtn.parentElement.appendChild(ok);setTimeout(function(){ok.remove();},2500);}
            })
            .catch(function(err){alert('Save failed: '+err.message);})
            .finally(function(){if(saveBtn)saveBtn.disabled=false;});
        });
      });
      document.querySelectorAll('.pill-cell').forEach(function(cell){
        var items=Array.from(cell.querySelectorAll('.pill,.group-badge'));
        if(!items.length)return;
        items.forEach(function(it){it.style.display='';});
        var ex=cell.querySelector('.pill-more-btn');if(ex)ex.remove();
        var maxShow=Math.min(items.length,4);
        for(var i=maxShow;i<items.length;i++){items[i].style.display='none';}
        while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){maxShow--;items[maxShow].style.display='none';}
        var hidden=items.length-maxShow;
        if(hidden>0){var btn=document.createElement('button');btn.className='pill-more-btn';btn.type='button';btn.textContent='+'+hidden+' more';btn.addEventListener('click',function(){items.forEach(function(it){it.style.display='';});cell.style.flexWrap='wrap';btn.remove();});cell.appendChild(btn);while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){items[maxShow-1].style.display='none';maxShow--;hidden++;btn.textContent='+'+hidden+' more';}}
      });
      filterUsers();
    })();
    </script>
    {{else}}
    <p class="empty-state">{{call .T "no_users"}}</p>
    {{end}}

    {{else if eq .AdminTab "groups"}}
    {{if .Groups}}
    <div class="groups-table" id="groups-table" role="table" aria-label="{{call .T "groups"}}">
      <div class="groups-table-header" role="row">
        <div class="gtcol gtcol-name" role="columnheader" style="gap:8px;align-items:center">
          <button type="button" class="filter-toggle-btn" id="groups-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button>
          <a href="/admin/groups?sort=name&dir={{if and (eq .GroupSort "name") (eq .GroupDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .GroupSort "name"}} active{{end}}">{{call .T "group"}}{{if eq .GroupSort "name"}} {{if eq .GroupDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
        </div>
        <div class="gtcol gtcol-cmds" role="columnheader">
          <a href="/admin/groups?sort=commands&dir={{if and (eq .GroupSort "commands") (eq .GroupDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .GroupSort "commands"}} active{{end}}">{{call .T "commands"}}{{if eq .GroupSort "commands"}} {{if eq .GroupDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
        </div>
        <div class="gtcol gtcol-hosts" role="columnheader">
          <a href="/admin/groups?sort=hosts&dir={{if and (eq .GroupSort "hosts") (eq .GroupDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .GroupSort "hosts"}} active{{end}}">{{call .T "hosts"}}{{if eq .GroupSort "hosts"}} {{if eq .GroupDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
        </div>
        <div class="gtcol gtcol-members" role="columnheader">
          <a href="/admin/groups?sort=members&dir={{if and (eq .GroupSort "members") (eq .GroupDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .GroupSort "members"}} active{{end}}">{{call .T "members"}}{{if eq .GroupSort "members"}} {{if eq .GroupDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
        </div>
        <div class="gtcol gtcol-runas" role="columnheader">
          <a href="/admin/groups?sort=runas&dir={{if and (eq .GroupSort "runas") (eq .GroupDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .GroupSort "runas"}} active{{end}}">{{call .T "sudo_run_as"}}{{if eq .GroupSort "runas"}} {{if eq .GroupDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
        </div>
      </div>
      <div class="groups-table-filter" id="groups-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="name" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="cmds" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="hosts" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="members" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div style="display:flex;align-items:center;gap:4px;padding:0 6px;min-width:0"><input type="text" class="gtcol-filter-input" data-col="runas" placeholder="{{call .T "search"}}…" autocomplete="off" style="flex:1;min-width:0"><button type="button" class="filter-clear-btn" id="groups-clear">{{call .T "clear_filter"}}</button></div>
      </div>
      <div class="groups-list">
      {{range .Groups}}
      <div class="group-wrapper">
      <div class="groups-table-row" id="group-{{.Name}}" role="row">
        <div class="gtcol gtcol-name" role="cell" style="gap:8px;align-items:center;flex-wrap:wrap;justify-content:space-between">
          <a href="/admin/groups#group-{{.Name}}" class="group-badge group-badge-link">{{.Name}}</a>
          {{if $.CanEditClaims}}<button type="button" class="claims-toggle-btn" style="margin-left:auto" data-claims-target="gclaims-{{.GroupID}}"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;vertical-align:-1px"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>Claims <span class="claims-chevron">▾</span></button>{{end}}
        </div>
        <div class="gtcol gtcol-cmds" role="cell">
          <div class="pill-cell">{{if .AllCmds}}<span class="pill cmd">{{call $.T "all_commands"}}</span>{{else}}{{range .CmdList}}<span class="pill cmd">{{.}}</span>{{end}}{{end}}</div>
        </div>
        <div class="gtcol gtcol-hosts" role="cell">
          <div class="pill-cell">{{if .AllHosts}}<span class="summary-chip all" style="background:var(--host-bg);color:var(--host-fg);border-color:var(--host-fg)">{{call $.T "all_hosts"}}</span>{{else}}{{range .HostList}}<a href="/history?hostname={{.}}" class="pill host">{{.}}</a>{{end}}{{end}}</div>
        </div>
        <div class="gtcol gtcol-members" role="cell">
          <div class="pill-cell">{{range .Members}}<a href="/access?user={{.}}" class="group-badge group-badge-link">{{.}}</a>{{end}}{{if not .Members}}<span class="row-sub" style="font-size:0.8125rem">{{call $.T "no_members"}}</span>{{end}}</div>
        </div>
        <div class="gtcol gtcol-runas" role="cell">
          {{if and .SudoRunAs (ne .SudoRunAs "root")}}<span class="pill cmd">{{.SudoRunAs}}</span>{{else}}<span class="row-sub" style="font-size:0.8125rem">root</span>{{end}}
        </div>
      </div>
      {{if $.CanEditClaims}}
      <div class="claims-panel" id="gclaims-{{.GroupID}}">
        <div class="claims-panel-title">Edit Claims — {{.Name}}</div>
        <form method="POST" action="/api/admin/groups/claims">
          <input type="hidden" name="group_id" value="{{.GroupID}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <div class="claims-form">
            <span class="claims-form-label">sudoCommands</span>
            <div class="claims-form-field"><input type="text" name="sudoCommands" value="{{.SudoCommands}}" placeholder="e.g. ALL or /usr/bin/apt,/usr/bin/systemctl"><span class="claims-form-hint">Commands this group may run via sudo. Comma-separated paths, or ALL.</span></div>
            <span class="claims-form-label">sudoHosts</span>
            <div class="claims-form-field"><input type="text" name="sudoHosts" value="{{.SudoHosts}}" placeholder="e.g. ALL or host1,host2"><span class="claims-form-hint">Hosts where sudo is permitted. Comma-separated hostnames, or ALL.</span></div>
            <span class="claims-form-label">sudoRunAsUser</span>
            <div class="claims-form-field"><input type="text" name="sudoRunAsUser" value="{{.SudoRunAs}}" placeholder="root"><span class="claims-form-hint">User to run as (sudo -u). Defaults to root if blank.</span></div>
            <span class="claims-form-label">sudoRunAsGroup</span>
            <div class="claims-form-field"><input type="text" name="sudoRunAsGroup" value="{{.SudoRunAsGroup}}" placeholder=""><span class="claims-form-hint">Group to run as (sudo -g). Optional.</span></div>
            <span class="claims-form-label">sudoOptions</span>
            <div class="claims-form-field"><input type="text" name="sudoOptions" value="{{.SudoOptions}}" placeholder=""><span class="claims-form-hint">Extra sudoers options, e.g. NOPASSWD, NOEXEC. Comma-separated.</span></div>
            <span class="claims-form-label">accessHosts</span>
            <div class="claims-form-field"><input type="text" name="accessHosts" value="{{.AccessHosts}}" placeholder="e.g. host1,host2"><span class="claims-form-hint">Hosts this group may log in to via PAM. Comma-separated. Blank = no PAM restriction.</span></div>
            <div class="claims-form-actions">
              <button type="submit" class="saction-btn">Save</button>
              <button type="button" class="saction-btn claims-panel-cancel" data-claims-target="gclaims-{{.GroupID}}">Cancel</button>
            </div>
          </div>
          {{if .OtherClaims}}
          <div class="claims-readonly">
            <div style="font-size:0.75rem;font-weight:600;color:var(--text-3);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:6px">Read-only claims (not managed by identree)</div>
            {{range .OtherClaims}}<div class="claims-readonly-row"><span class="claims-readonly-key">{{.Key}}</span><span class="claims-readonly-val">{{.Value}}</span></div>{{end}}
          </div>
          {{end}}
        </form>
      </div>
      {{end}}
      </div>
      {{end}}
      </div>
    </div>
    <div class="pagination-bar" id="groups-pagination"></div>
    <div id="groups-filter-empty-msg" style="display:none" class="empty-state">No results match your filter</div>
    <script nonce="{{.CSPNonce}}">
    (function(){
      var groupsPage=1,groupsPs={{.DefaultPageSize}};
      function renderGroupsPager(vis){
        var bar=document.getElementById('groups-pagination');
        if(!bar)return;
        var total=vis.length,totalPages=Math.max(1,Math.ceil(total/groupsPs));
        if(groupsPage>totalPages)groupsPage=1;
        var start=(groupsPage-1)*groupsPs;
        var allWrappers=Array.from(document.querySelectorAll('.group-wrapper'));
        allWrappers.forEach(function(r){r.style.display='none';});
        vis.slice(start,start+groupsPs).forEach(function(r){r.style.display='';});
        var emptyMsg=document.getElementById('groups-filter-empty-msg');
        if(emptyMsg){emptyMsg.style.display=total===0?'':'none';}
        if(totalPages<=1&&total>0){bar.innerHTML='';vis.forEach(function(r){r.style.display='';});return;}
        if(total===0){bar.innerHTML='';return;}
        bar.innerHTML='<button class="pagination-btn" '+(groupsPage<=1?'disabled':'')+'>&#8592;</button><span class="pagination-info">'+(start+1)+'&#8211;'+Math.min(start+groupsPs,total)+' of '+total+'</span><button class="pagination-btn" '+(groupsPage>=totalPages?'disabled':'')+'>&#8594;</button><select class="pagination-size-select">'+[15,30,50,100].map(function(n){return'<option value="'+n+'"'+(n===groupsPs?' selected':'')+'>'+n+' per page</option>';}).join('')+'</select>';
        var btns=bar.querySelectorAll('.pagination-btn');
        if(!btns[0].disabled)btns[0].addEventListener('click',function(){groupsPage--;filterGroups();});
        if(!btns[1].disabled)btns[1].addEventListener('click',function(){groupsPage++;filterGroups();});
        bar.querySelector('.pagination-size-select').addEventListener('change',function(){groupsPs=parseInt(this.value);groupsPage=1;filterGroups();});
      }
      function filterGroups(){
        var filters={};
        document.querySelectorAll('.gtcol-filter-input').forEach(function(inp){
          filters[inp.dataset.col]=inp.value.toLowerCase().trim();
        });
        var allWrappers=Array.from(document.querySelectorAll('.group-wrapper'));
        var vis=allWrappers.filter(function(wrapper){
          for(var col in filters){
            if(!filters[col]) continue;
            var cell=wrapper.querySelector('.gtcol-'+col);
            if(cell&&cell.textContent.toLowerCase().indexOf(filters[col])===-1){return false;}
          }
          return true;
        });
        renderGroupsPager(vis);
      }
      document.querySelectorAll('.gtcol-filter-input').forEach(function(inp){
        inp.addEventListener('input',function(){groupsPage=1;filterGroups();});
      });
      var gc=document.getElementById('groups-clear');
      if(gc)gc.addEventListener('click',function(){document.querySelectorAll('.gtcol-filter-input').forEach(function(i){i.value='';});groupsPage=1;filterGroups();});
      (function(){var ftb=document.getElementById('groups-filter-toggle');var ftr=document.getElementById('groups-filter-row');if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      // Claims panel toggles
      function setClaimsToggleState(btn,open){
        var span=btn.querySelector('.claims-chevron');
        if(span){span.textContent=open?'▴':'▾';}
      }
      document.querySelectorAll('.claims-toggle-btn').forEach(function(btn){
        btn.addEventListener('click',function(){
          var id=btn.dataset.claimsTarget;
          var panel=document.getElementById(id);
          if(!panel)return;
          var open=panel.style.display!=='none'&&panel.style.display!=='';
          panel.style.display=open?'none':'block';
          setClaimsToggleState(btn,!open);
        });
      });
      document.querySelectorAll('.claims-panel-cancel').forEach(function(btn){
        btn.addEventListener('click',function(){
          var id=btn.dataset.claimsTarget;
          var panel=document.getElementById(id);
          if(panel){panel.style.display='none';}
          var toggle=document.querySelector('[data-claims-target="'+id+'"].claims-toggle-btn');
          if(toggle){setClaimsToggleState(toggle,false);}
        });
      });
      // Submit claims forms via fetch to keep panel open
      document.querySelectorAll('.claims-panel form').forEach(function(form){
        form.addEventListener('submit',function(e){
          e.preventDefault();
          var saveBtn=form.querySelector('button[type=submit]');
          if(saveBtn)saveBtn.disabled=true;
          fetch(form.action,{method:'POST',headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(form))})
            .then(function(r){if(r.status===401){window.location.href='/login';return;}return r.ok?r.json():r.text().then(function(t){throw new Error(t);});})
            .then(function(){
              var ok=document.createElement('span');
              ok.textContent=' ✓ Saved';ok.style.cssText='color:var(--success);font-size:0.8125rem;font-weight:600';
              if(saveBtn){saveBtn.parentElement.appendChild(ok);setTimeout(function(){ok.remove();},2500);}
            })
            .catch(function(err){alert('Save failed: '+err.message);})
            .finally(function(){if(saveBtn)saveBtn.disabled=false;});
        });
      });
      document.querySelectorAll('.pill-cell').forEach(function(cell){
        var items=Array.from(cell.querySelectorAll('.pill,.group-badge'));
        if(!items.length)return;
        items.forEach(function(it){it.style.display='';});
        var ex=cell.querySelector('.pill-more-btn');if(ex)ex.remove();
        var maxShow=Math.min(items.length,4);
        for(var i=maxShow;i<items.length;i++){items[i].style.display='none';}
        while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){maxShow--;items[maxShow].style.display='none';}
        var hidden=items.length-maxShow;
        if(hidden>0){var btn=document.createElement('button');btn.className='pill-more-btn';btn.type='button';btn.textContent='+'+hidden+' more';btn.addEventListener('click',function(){items.forEach(function(it){it.style.display='';});cell.style.flexWrap='wrap';btn.remove();});cell.appendChild(btn);while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){items[maxShow-1].style.display='none';maxShow--;hidden++;btn.textContent='+'+hidden+' more';}}
      });
      filterGroups();
    })();
    </script>
    {{else}}
    <p class="empty-state">{{call .T "no_groups"}}</p>
    {{end}}

    {{else if eq .AdminTab "hosts"}}
    {{if .Hosts}}
    <div class="hosts-table" id="hosts-table" role="table" aria-label="{{call .T "hosts"}}">
      <div class="hosts-table-header" role="row">
        <div class="gtcol gtcol-hhost" role="columnheader" style="gap:10px;align-items:center;flex-wrap:wrap">
          <button type="button" class="filter-toggle-btn" id="hosts-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button>
          <a href="/admin/hosts?sort=hostname{{if .GroupFilter}}&group={{.GroupFilter}}{{end}}&dir={{if and (eq .HostSort "hostname") (eq .HostDir "asc")}}desc{{else}}asc{{end}}" class="col-sort-link{{if eq .HostSort "hostname"}} active{{end}}">{{call .T "host"}}{{if eq .HostSort "hostname"}} {{if eq .HostDir "asc"}}↑{{else}}↓{{end}}{{end}}</a>
          {{if .AllGroups}}<form method="GET" action="/admin/hosts" style="display:inline;margin:0"><select name="group" class="col-filter-select" aria-label="{{call .T "aria_filter_group"}}"><option value="">{{call .T "all_groups"}}</option>{{range .AllGroups}}<option value="{{.}}" {{if eq . $.GroupFilter}}selected{{end}}>{{.}}</option>{{end}}</select></form>{{end}}
          {{if .GroupFilter}}<a href="/admin/hosts" style="font-size:0.75rem;color:var(--text-3)">{{call .T "clear_filter"}}</a>{{end}}
        </div>
        <div class="gtcol gtcol-hbreakglass" role="columnheader"><span class="col-sort-link">{{call .T "breakglass"}}</span></div>
        <div class="gtcol gtcol-hactions" role="columnheader" style="align-items:center;flex-wrap:wrap;gap:8px">
          <span class="col-sort-link">{{call .T "action"}}</span>
          {{if .HasEscrowedHosts}}<form method="POST" action="/api/hosts/rotate-all" style="display:inline;margin:0"><input type="hidden" name="username" value="{{.Username}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="csrf_ts" value="{{.CSRFTs}}"><button type="submit" class="saction-btn saction-rotate-all" data-confirm="{{call .T "confirm_rotate_all"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.5"/></svg>{{call .T "rotate_all"}}</button></form>{{end}}
        </div>
      </div>
      <div class="hosts-table-filter" id="hosts-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="hhost" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="hbreakglass" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div style="display:flex;justify-content:flex-end;align-items:center;padding:0 6px"><button type="button" class="filter-clear-btn" id="hosts-clear">{{call .T "clear_filter"}}</button></div>
      </div>
      {{range .Hosts}}
      <div class="hosts-table-row" role="row">
        <div class="gtcol gtcol-hhost" role="cell" style="flex-wrap:wrap;gap:4px;align-items:center">
          <a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a>{{if .Group}}<span class="host-group">{{.Group}}</span>{{end}}
        </div>
        <div class="gtcol gtcol-hbreakglass" role="cell">
          {{if .Escrowed}}
            <span style="font-size:0.8125rem;color:{{if .EscrowExpired}}var(--danger){{else}}var(--success){{end}}">{{if .EscrowExpired}}{{call $.T "breakglass_expired"}}{{else}}{{call $.T "breakglass_escrowed"}}{{end}}<span style="color:var(--text-3);font-weight:400"> ({{.EscrowAge}} {{call $.T "ago"}})</span></span>
            {{if .EscrowLink}}<a href="{{.EscrowLink}}" target="_blank" class="btn btn-sm" style="margin-top:4px">{{call $.T "view"}}</a>{{end}}
          {{end}}
        </div>
        <div class="gtcol gtcol-hactions" role="cell" style="gap:6px;flex-wrap:nowrap;align-items:center;justify-content:flex-end">
          {{if gt .ActiveSessionCount 0}}<a href="/?host={{.Hostname}}" class="saction-btn saction-sessions saction-primary"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>{{call $.T "sessions"}} ({{.ActiveSessionCount}})</a>{{end}}
          {{if .EscrowRevealable}}<button type="button" class="saction-btn reveal-password-btn" data-hostname="{{.Hostname}}" data-username="{{$.Username}}" data-csrf="{{$.CSRFToken}}" data-ts="{{$.CSRFTs}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>{{call $.T "reveal"}}</button>{{end}}
          <a href="/history?hostname={{.Hostname}}" class="saction-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call $.T "history"}}</a>
          <form method="POST" action="/api/hosts/rotate" style="display:inline">
            <input type="hidden" name="hostname" value="{{.Hostname}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="saction-btn saction-rotate" data-confirm="{{printf (call $.T "confirm_rotate_host") .Hostname}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.5"/></svg>{{call $.T "rotate"}}</button>
          </form>
          <button class="saction-btn saction-danger remove-host-btn" data-hostname="{{.Hostname}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>{{call $.T "remove_host"}}</button>
        </div>
      </div>
      {{end}}
    </div>
    <div class="pagination-bar" id="hosts-pagination"></div>
    <div id="hosts-filter-empty-msg" style="display:none" class="empty-state">No results match your filter</div>
    <script nonce="{{.CSPNonce}}">
    (function(){
      var hostsPage=1,hostsPs={{.DefaultPageSize}};
      function renderHostsPager(vis){
        var bar=document.getElementById('hosts-pagination');
        if(!bar)return;
        var total=vis.length,totalPages=Math.max(1,Math.ceil(total/hostsPs));
        if(hostsPage>totalPages)hostsPage=1;
        var start=(hostsPage-1)*hostsPs;
        var allRows=Array.from(document.querySelectorAll('#hosts-table .hosts-table-row'));
        allRows.forEach(function(r){r.style.display='none';});
        vis.slice(start,start+hostsPs).forEach(function(r){r.style.display='';});
        var emptyMsg=document.getElementById('hosts-filter-empty-msg');
        if(emptyMsg){emptyMsg.style.display=total===0?'':'none';}
        if(totalPages<=1&&total>0){bar.innerHTML='';vis.forEach(function(r){r.style.display='';});return;}
        if(total===0){bar.innerHTML='';return;}
        bar.innerHTML='<button class="pagination-btn" '+(hostsPage<=1?'disabled':'')+'>&#8592;</button><span class="pagination-info">'+(start+1)+'&#8211;'+Math.min(start+hostsPs,total)+' of '+total+'</span><button class="pagination-btn" '+(hostsPage>=totalPages?'disabled':'')+'>&#8594;</button><select class="pagination-size-select">'+[15,30,50,100].map(function(n){return'<option value="'+n+'"'+(n===hostsPs?' selected':'')+'>'+n+' per page</option>';}).join('')+'</select>';
        var btns=bar.querySelectorAll('.pagination-btn');
        if(!btns[0].disabled)btns[0].addEventListener('click',function(){hostsPage--;filterHosts();});
        if(!btns[1].disabled)btns[1].addEventListener('click',function(){hostsPage++;filterHosts();});
        bar.querySelector('.pagination-size-select').addEventListener('change',function(){hostsPs=parseInt(this.value);hostsPage=1;filterHosts();});
      }
      function filterHosts(){
        var filters={};
        document.querySelectorAll('#hosts-table .gtcol-filter-input').forEach(function(inp){ filters[inp.dataset.col]=inp.value.toLowerCase().trim(); });
        var allRows=Array.from(document.querySelectorAll('#hosts-table .hosts-table-row'));
        var vis=allRows.filter(function(row){
          for(var col in filters){ if(!filters[col]) continue; var cell=row.querySelector('.gtcol-'+col); if(cell&&cell.textContent.toLowerCase().indexOf(filters[col])===-1){return false;} }
          return true;
        });
        renderHostsPager(vis);
      }
      document.querySelectorAll('#hosts-table .gtcol-filter-input').forEach(function(inp){ inp.addEventListener('input',function(){hostsPage=1;filterHosts();}); });
      var hc=document.getElementById('hosts-clear');
      if(hc)hc.addEventListener('click',function(){document.querySelectorAll('#hosts-table .gtcol-filter-input').forEach(function(i){i.value='';});hostsPage=1;filterHosts();});
      (function(){var ftb=document.getElementById('hosts-filter-toggle');var ftr=document.getElementById('hosts-filter-row');if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      document.querySelectorAll('.saction-rotate,.saction-rotate-all').forEach(function(btn){
        btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});
      });
      document.querySelectorAll('.reveal-password-btn').forEach(function(btn){
        btn.addEventListener('click',function(){
          var hostname=btn.dataset.hostname;
          btn.disabled=true;
          fetch('/api/breakglass/reveal',{method:'POST',body:JSON.stringify({hostname:hostname}),headers:Object.assign({'Content-Type':'application/json'},_csrf)})
            .then(function(r){
              if(r.status===401){window.location.href='/login';return;}
              if(!r.ok)return r.text().then(function(t){throw new Error(t.trim()||r.statusText);});
              return r.json();
            })
            .then(function(data){
              var modal=document.getElementById('reveal-modal');
              var pw=data.password||'';
              modal.querySelector('#reveal-modal-host').textContent=hostname;
              var pwEl=modal.querySelector('#reveal-modal-password');
              pwEl.textContent=pw;
              pwEl.style.filter='blur(6px)';
              var toggle=modal.querySelector('#reveal-toggle');
              toggle.textContent='{{call .T "show"}}';
              toggle.onclick=function(){
                var hidden=pwEl.style.filter!=='none';
                pwEl.style.filter=hidden?'none':'blur(6px)';
                toggle.textContent=hidden?'{{call .T "hide"}}':'{{call .T "show"}}';
              };
              var copyBtn=modal.querySelector('#reveal-copy');
              var rotateNote=modal.querySelector('#reveal-modal-rotate-note');
              if(rotateNote)rotateNote.style.display='none';
              var rotated=false;
              copyBtn.onclick=function(){
                navigator.clipboard&&navigator.clipboard.writeText(pw);
                copyBtn.textContent='{{call .T "copied"}}';
                setTimeout(function(){copyBtn.textContent='{{call .T "copy"}}';},2000);
                if(!rotated){
                  rotated=true;
                  fetch('/api/hosts/rotate',{method:'POST',body:body,headers:{'Content-Type':'application/x-www-form-urlencoded'}})
                    .then(function(rr){if(rr.status===401){window.location.href='/login';return;}if(rr.ok&&rotateNote)rotateNote.style.display='block';})
                    .catch(function(){});
                }
              };
              modal.style.display='flex';
            })
            .catch(function(err){alert('Reveal failed: '+err.message);})
            .finally(function(){btn.disabled=false;});
        });
      });
      document.addEventListener('DOMContentLoaded',function(){
        var revealModal=document.getElementById('reveal-modal');
        if(!revealModal)return;
        revealModal.addEventListener('click',function(e){if(e.target===revealModal)revealModal.style.display='none';});
        ['reveal-modal-x','reveal-modal-close'].forEach(function(id){
          var btn=document.getElementById(id);
          if(btn)btn.addEventListener('click',function(){revealModal.style.display='none';});
        });
        // Focus trap for reveal modal (L8)
        revealModal.addEventListener('keydown',function(e){
          if(e.key!=='Tab')return;
          var focusable=Array.from(revealModal.querySelectorAll('button,input,[tabindex="0"]')).filter(function(el){return !el.disabled&&el.offsetParent!==null;});
          if(!focusable.length){e.preventDefault();return;}
          var first=focusable[0],last=focusable[focusable.length-1];
          if(e.shiftKey){if(document.activeElement===first){e.preventDefault();last.focus();}}
          else{if(document.activeElement===last){e.preventDefault();first.focus();}}
        });
        document.addEventListener('keydown',function(e){
          if(e.key==='Escape'){
            if(revealModal.style.display!=='none')revealModal.style.display='none';
            var rm=document.getElementById('remove-modal');
            if(rm&&rm.classList.contains('open'))rm.classList.remove('open');
          }
        });
        // L13: associate config inputs with their label text via aria-label
        document.querySelectorAll('.config-table-row').forEach(function(row){
          var labelEl=row.querySelector('.config-label-env');
          var input=row.querySelector('.config-input:not([disabled])');
          if(labelEl&&input&&!input.getAttribute('aria-label')){input.setAttribute('aria-label',labelEl.textContent.trim());}
        });
      });
      filterHosts();
    })();
    </script>
    <div id="reveal-modal" style="display:none;position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,0.55);align-items:center;justify-content:center" role="dialog" aria-modal="true" aria-labelledby="reveal-modal-title">
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px 28px 24px;max-width:520px;width:calc(100% - 40px);box-shadow:0 8px 32px rgba(0,0,0,0.25)">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
          <span id="reveal-modal-title" style="font-weight:600;font-size:1rem">{{call .T "breakglass_password"}}</span>
          <button id="reveal-modal-x" type="button" style="background:none;border:none;cursor:pointer;color:var(--text-2);font-size:1.3rem;line-height:1;padding:2px 6px" aria-label="{{call .T "close"}}">&times;</button>
        </div>
        <div style="font-size:0.85rem;color:var(--text-2);margin-bottom:14px">{{call .T "reveal_host_label"}}: <strong id="reveal-modal-host"></strong></div>
        <div style="background:var(--danger-bg);border:1px solid var(--danger-border);color:var(--danger);border-radius:8px;padding:10px 14px;font-size:0.8125rem;margin-bottom:8px">{{call .T "reveal_audit_notice"}}</div>
        <div id="reveal-modal-rotate-note" style="display:none;background:rgba(217,119,6,0.1);border:1px solid rgba(217,119,6,0.35);color:#d97706;border-radius:8px;padding:8px 14px;font-size:0.8125rem;margin-bottom:8px">{{call .T "reveal_rotation_notice"}}</div>
        <div style="margin-bottom:16px"></div>
        <div style="display:flex;align-items:center;gap:10px;background:var(--bg-alt,var(--bg));border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-family:monospace;font-size:0.95rem;margin-bottom:16px">
          <span id="reveal-modal-password" style="flex:1;word-break:break-all"></span>
          <button id="reveal-toggle" type="button" style="background:none;border:1px solid var(--border);border-radius:6px;padding:3px 10px;font-size:0.8rem;cursor:pointer;white-space:nowrap;color:var(--text-2)">{{call .T "show"}}</button>
          <button id="reveal-copy" type="button" style="background:none;border:1px solid var(--border);border-radius:6px;padding:3px 10px;font-size:0.8rem;cursor:pointer;white-space:nowrap;color:var(--text-2)">{{call .T "copy"}}</button>
        </div>
        <div style="text-align:right"><button id="reveal-modal-close" type="button" style="background:none;border:1px solid var(--border);border-radius:8px;padding:7px 18px;cursor:pointer;font-size:0.875rem;color:var(--text)">{{call .T "close"}}</button></div>
      </div>
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_known_hosts"}}</p>
    {{end}}
    {{if .DeployEnabled}}<div style="margin-top:14px"><button id="deploy-open-btn" class="btn btn-primary" title="{{call .T "deploy_title"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:5px"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>{{call .T "deploy_btn"}}</button></div>{{end}}

    {{else if eq .AdminTab "sudo-rules"}}
    {{if .SudoRules}}
    <div class="list" role="list">
      {{range .SudoRules}}
      <div class="row" role="listitem" style="flex-direction:column;align-items:stretch;gap:0">
        <div class="host-row-header">
          <div class="host-row-header-info">
            <span class="user-name">{{.Group}}</span>
            {{range splitCommaTemplate .Commands}}<span class="pill cmd" style="font-size:0.78rem">{{.}}</span>{{end}}
            {{if .Hosts}}<span class="row-sub" style="display:inline">{{call $.T "sudo_rules_hosts"}}: {{.Hosts}}</span>{{end}}
          </div>
          <div class="host-row-header-actions">
            <button type="button" class="btn" onclick="sudoEditRule(this)"
              data-group="{{.Group}}"
              data-hosts="{{.Hosts}}"
              data-commands="{{.Commands}}"
              data-run-as-user="{{.RunAsUser}}"
              data-run-as-group="{{.RunAsGroup}}"
              data-options="{{.Options}}">{{call $.T "edit"}}</button>
            <form method="POST" action="/api/sudo-rules/delete" style="display:inline">
              <input type="hidden" name="group" value="{{.Group}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <button type="submit" class="btn btn-danger confirm-submit" data-confirm="{{printf (call $.T "sudo_rules_confirm_delete") .Group}}">{{call $.T "delete"}}</button>
            </form>
          </div>
        </div>
        {{if or .RunAsUser .RunAsGroup .Options}}
        <div class="host-row-users" style="padding-top:4px;gap:4px">
          {{if .RunAsUser}}<span class="row-sub">{{call $.T "sudo_rules_run_as_user"}}: {{.RunAsUser}}</span>{{end}}
          {{if .RunAsGroup}}<span class="row-sub">{{call $.T "sudo_rules_run_as_group"}}: {{.RunAsGroup}}</span>{{end}}
          {{if .Options}}<span class="row-sub">{{call $.T "sudo_rules_options"}}: {{.Options}}</span>{{end}}
        </div>
        {{end}}
      </div>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">{{call .T "sudo_rules_empty"}}</p>
    {{end}}

    <div class="hosts-toolbar" style="margin-top:24px">
      <button type="button" class="btn btn-primary" id="sudo-add-btn" onclick="sudoShowAdd()">{{call .T "sudo_rules_add"}}</button>
    </div>

    <div id="sudo-form-card" style="display:none;margin-top:16px" class="info-section">
      <h3 id="sudo-form-title">{{call .T "sudo_rules_add"}}</h3>
      <form id="sudo-rule-form" method="POST" action="/api/sudo-rules/add">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <input type="hidden" id="sudo-form-action" name="_action" value="add">
        <table class="info-table" style="width:100%;max-width:640px">
          <tr>
            <td class="info-label"><label for="sudo-group">{{call .T "sudo_rules_group"}}</label></td>
            <td><input type="text" id="sudo-group" name="group" required pattern="[a-z_][a-z0-9_.-]*" maxlength="256" class="text-input" placeholder="e.g. sysadmins" autocomplete="off"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="sudo-commands">{{call .T "sudo_rules_commands"}}</label></td>
            <td>
              <input type="text" id="sudo-commands" name="commands" required class="text-input" placeholder="/usr/bin/apt,/usr/bin/systemctl" autocomplete="off">
              <div style="font-size:0.78rem;color:var(--text-2);margin-top:4px">{{call .T "sudo_rules_commands_hint"}}</div>
            </td>
          </tr>
          <tr>
            <td class="info-label"><label for="sudo-hosts">{{call .T "sudo_rules_hosts"}}</label></td>
            <td>
              <input type="text" id="sudo-hosts" name="hosts" class="text-input" placeholder="ALL" autocomplete="off">
              <div style="font-size:0.78rem;color:var(--text-2);margin-top:4px">{{call .T "sudo_rules_hosts_hint"}}</div>
            </td>
          </tr>
          <tr>
            <td class="info-label"><label for="sudo-run-as-user">{{call .T "sudo_rules_run_as_user"}}</label></td>
            <td><input type="text" id="sudo-run-as-user" name="run_as_user" class="text-input" placeholder="root (default)" autocomplete="off"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="sudo-run-as-group">{{call .T "sudo_rules_run_as_group"}}</label></td>
            <td><input type="text" id="sudo-run-as-group" name="run_as_group" class="text-input" placeholder="" autocomplete="off"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="sudo-options">{{call .T "sudo_rules_options"}}</label></td>
            <td><input type="text" id="sudo-options" name="options" class="text-input" placeholder="NOPASSWD" autocomplete="off"></td>
          </tr>
        </table>
        <div class="modal-actions" style="margin-top:16px">
          <button type="button" class="btn" onclick="sudoHideForm()">{{call .T "cancel"}}</button>
          <button type="submit" class="btn btn-primary">{{call .T "sudo_rules_save"}}</button>
        </div>
      </form>
    </div>
    <script nonce="{{.CSPNonce}}">
    function sudoShowAdd() {
      document.getElementById('sudo-form-title').textContent = {{call .T "sudo_rules_add"}};
      document.getElementById('sudo-rule-form').action = '/api/sudo-rules/add';
      document.getElementById('sudo-group').readOnly = false;
      document.getElementById('sudo-group').value = '';
      document.getElementById('sudo-commands').value = '';
      document.getElementById('sudo-hosts').value = '';
      document.getElementById('sudo-run-as-user').value = '';
      document.getElementById('sudo-run-as-group').value = '';
      document.getElementById('sudo-options').value = '';
      document.getElementById('sudo-form-card').style.display = '';
      document.getElementById('sudo-add-btn').style.display = 'none';
      document.getElementById('sudo-group').focus();
    }
    function sudoEditRule(btn) {
      document.getElementById('sudo-form-title').textContent = {{call .T "sudo_rules_edit"}};
      document.getElementById('sudo-rule-form').action = '/api/sudo-rules/update';
      document.getElementById('sudo-group').readOnly = true;
      document.getElementById('sudo-group').value = btn.dataset.group;
      document.getElementById('sudo-commands').value = btn.dataset.commands;
      document.getElementById('sudo-hosts').value = btn.dataset.hosts;
      document.getElementById('sudo-run-as-user').value = btn.dataset.runAsUser;
      document.getElementById('sudo-run-as-group').value = btn.dataset.runAsGroup;
      document.getElementById('sudo-options').value = btn.dataset.options;
      document.getElementById('sudo-form-card').style.display = '';
      document.getElementById('sudo-add-btn').style.display = 'none';
      document.getElementById('sudo-commands').focus();
    }
    function sudoHideForm() {
      document.getElementById('sudo-form-card').style.display = 'none';
      document.getElementById('sudo-add-btn').style.display = '';
    }
    document.querySelectorAll('.confirm-submit').forEach(function(btn){
      btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});
    });
    </script>

    {{else if eq .AdminTab "notifications"}}
    {{range .FlashErrors}}<div class="banner banner-error" role="alert">{{.}}</div>{{end}}

    <!-- ── Notification Channels ──────────────────────────────────────── -->
    <h3 style="margin-bottom:12px">{{call .T "notify_channels"}}</h3>
    {{if .NotifyChannels}}
    <div class="list" role="list">
      {{range .NotifyChannels}}
      <div class="row" role="listitem">
        <div class="host-row-header">
          <div class="host-row-header-info">
            <span class="user-name">{{.Name}}</span>
            <span class="pill">{{.Backend}}</span>
            {{if .URL}}<span class="pill" style="font-size:0.75rem;color:var(--text-3)">{{.URL}}</span>{{end}}
          </div>
          <div class="host-row-header-actions">
            <form method="POST" action="/api/admin/test-channel" style="display:inline">
              <input type="hidden" name="channel" value="{{.Name}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <button type="submit" class="btn btn-sm">{{call $.T "notify_test"}}</button>
            </form>
            <form method="POST" action="/api/notification/channels/delete" style="display:inline">
              <input type="hidden" name="name" value="{{.Name}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <button type="submit" class="btn btn-danger btn-sm confirm-submit" data-confirm="Delete channel {{.Name}}?">{{call $.T "notify_delete"}}</button>
            </form>
          </div>
        </div>
      </div>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">{{call .T "notify_no_channels"}}</p>
    {{end}}

    <div id="channel-form-card" style="display:none;margin-top:16px" class="info-section">
      <h3>{{call .T "notify_add_channel"}}</h3>
      <form method="POST" action="/api/notification/channels/add">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <table class="info-table" style="width:100%;max-width:640px">
          <tr>
            <td class="info-label"><label for="ch-name">{{call .T "notify_channel_name_label"}}</label></td>
            <td><input type="text" id="ch-name" name="name" required pattern="[a-z0-9][a-z0-9._-]*" maxlength="64" class="text-input" placeholder="e.g. ops-slack"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="ch-backend">{{call .T "notify_backend_label"}}</label></td>
            <td><select id="ch-backend" name="backend" class="text-input" required>
              <option value="ntfy">ntfy</option>
              <option value="slack">Slack</option>
              <option value="discord">Discord</option>
              <option value="apprise">Apprise</option>
              <option value="webhook">Webhook (generic)</option>
              <option value="custom">Custom command</option>
            </select></td>
          </tr>
          <tr>
            <td class="info-label"><label for="ch-url">{{call .T "notify_channel_url_label"}}</label></td>
            <td><input type="url" id="ch-url" name="url" class="text-input" placeholder="https://hooks.slack.com/..."></td>
          </tr>
        </table>
        <p style="font-size:0.8rem;color:var(--text-3);margin:8px 0">Tokens and commands are injected via environment variables: <code>IDENTREE_NOTIFY_CHANNEL_&lt;NAME&gt;_TOKEN</code> / <code>_COMMAND</code></p>
        <div class="modal-actions" style="margin-top:12px">
          <button type="button" class="btn" onclick="document.getElementById('channel-form-card').style.display='none';document.getElementById('ch-add-btn').style.display='';document.getElementById('ch-add-btn').setAttribute('aria-expanded','false')">{{call .T "notify_cancel"}}</button>
          <button type="submit" class="btn btn-primary">{{call .T "notify_add_channel"}}</button>
        </div>
      </form>
    </div>
    <div style="margin-top:14px">
      <button type="button" id="ch-add-btn" class="btn btn-primary" aria-expanded="false" onclick="document.getElementById('channel-form-card').style.display='';this.style.display='none';this.setAttribute('aria-expanded','true')">{{call .T "notify_add_channel"}}</button>
    </div>

    <!-- ── Routing Rules ─────────────────────────────────────────────── -->
    <h3 style="margin-top:32px;margin-bottom:12px">{{call .T "notify_routes"}}</h3>
    <p style="font-size:0.85rem;color:var(--text-3);margin-bottom:12px">{{call .T "notify_routes_desc"}}</p>
    {{if .NotifyRoutes}}
    <div class="list" role="list">
      {{range $i, $r := .NotifyRoutes}}
      <div class="row" role="listitem">
        <div class="host-row-header">
          <div class="host-row-header-info" style="gap:6px;flex-wrap:wrap">
            {{range .Channels}}<span class="pill">{{.}}</span>{{end}}
            <span style="color:var(--text-3);font-size:0.8rem">&larr;</span>
            {{range .Events}}<span class="pill cmd">{{.}}</span>{{end}}
            {{if .Hosts}}{{range .Hosts}}<span class="pill" style="background:var(--surface-2)">{{.}}</span>{{end}}{{end}}
            {{if .Users}}{{range .Users}}<span class="pill" style="background:var(--surface-2)">user:{{.}}</span>{{end}}{{end}}
          </div>
          <div class="host-row-header-actions">
            <form method="POST" action="/api/notification/routes/delete" style="display:inline">
              <input type="hidden" name="index" value="{{$i}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <button type="submit" class="btn btn-danger btn-sm confirm-submit" data-confirm="Delete this route?">{{call $.T "notify_delete"}}</button>
            </form>
          </div>
        </div>
      </div>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">{{call .T "notify_no_routes"}}</p>
    {{end}}

    <div id="route-form-card" style="display:none;margin-top:16px" class="info-section">
      <h3>{{call .T "notify_add_route"}}</h3>
      <form method="POST" action="/api/notification/routes/add">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <table class="info-table" style="width:100%;max-width:640px">
          <tr>
            <td class="info-label"><label for="rt-channels">{{call .T "notify_channels"}}</label></td>
            <td><input type="text" id="rt-channels" name="channels" required class="text-input" placeholder="ops-slack, oncall-ntfy"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="rt-events">{{call .T "notify_events_label"}}</label></td>
            <td><input type="text" id="rt-events" name="events" required class="text-input" placeholder="* or challenge_created, challenge_approved"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="rt-hosts">{{call .T "notify_hosts_label"}}</label></td>
            <td><input type="text" id="rt-hosts" name="hosts" class="text-input" placeholder="*.prod, bastion-* (empty = all)"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="rt-users">{{call .T "notify_users_label"}}</label></td>
            <td><input type="text" id="rt-users" name="users" class="text-input" placeholder="* (empty = all)"></td>
          </tr>
        </table>
        <div class="modal-actions" style="margin-top:12px">
          <button type="button" class="btn" onclick="document.getElementById('route-form-card').style.display='none';document.getElementById('rt-add-btn').style.display='';document.getElementById('rt-add-btn').setAttribute('aria-expanded','false')">{{call .T "notify_cancel"}}</button>
          <button type="submit" class="btn btn-primary">{{call .T "notify_add_route"}}</button>
        </div>
      </form>
    </div>
    <div style="margin-top:14px">
      <button type="button" id="rt-add-btn" class="btn btn-primary" aria-expanded="false" onclick="document.getElementById('route-form-card').style.display='';this.style.display='none';this.setAttribute('aria-expanded','true')">{{call .T "notify_add_route"}}</button>
    </div>

    <!-- ── My Notification Preferences ────────────────────────────────── -->
    <h3 style="margin-top:32px;margin-bottom:12px">{{call .T "notify_preferences"}}</h3>
    <p style="font-size:0.85rem;color:var(--text-3);margin-bottom:12px">{{call .T "notify_preferences_desc"}}</p>

    <div class="info-section">
      <form method="POST" action="/api/admin/notification-preferences">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <table class="info-table" style="width:100%;max-width:640px">
          <tr>
            <td class="info-label"><label for="pref-channels">{{call .T "notify_channels"}}</label></td>
            <td><input type="text" id="pref-channels" name="channels" class="text-input" value="{{if .MyNotifyPref}}{{range $i, $c := .MyNotifyPref.Channels}}{{if $i}}, {{end}}{{$c}}{{end}}{{end}}" placeholder="ops-slack, oncall-ntfy">
            {{if .ChannelNames}}<p style="font-size:0.75rem;color:var(--text-3);margin:2px 0">{{call .T "notify_pref_available"}} {{range $i, $n := .ChannelNames}}{{if $i}}, {{end}}{{$n}}{{end}}</p>{{end}}</td>
          </tr>
          <tr>
            <td class="info-label"><label for="pref-events">{{call .T "notify_events_label"}}</label></td>
            <td><input type="text" id="pref-events" name="events" class="text-input" value="{{if .MyNotifyPref}}{{range $i, $e := .MyNotifyPref.Events}}{{if $i}}, {{end}}{{$e}}{{end}}{{end}}" placeholder="* (all) or challenge_created, challenge_approved"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="pref-hosts">{{call .T "notify_hosts_label"}}</label></td>
            <td><input type="text" id="pref-hosts" name="hosts" class="text-input" value="{{if .MyNotifyPref}}{{range $i, $h := .MyNotifyPref.Hosts}}{{if $i}}, {{end}}{{$h}}{{end}}{{end}}" placeholder="empty = all hosts"></td>
          </tr>
          <tr>
            <td class="info-label"><label for="pref-enabled">{{call .T "notify_pref_enabled_label"}}</label></td>
            <td><input type="checkbox" id="pref-enabled" name="enabled" value="true" {{if and .MyNotifyPref .MyNotifyPref.Enabled}}checked{{end}}></td>
          </tr>
        </table>
        <div class="modal-actions" style="margin-top:12px">
          {{if .MyNotifyPref}}<button type="submit" name="action" value="delete" class="btn btn-danger confirm-submit" data-confirm="Remove your notification subscription?" style="margin-right:auto">{{call .T "notify_remove_pref"}}</button>{{end}}
          <button type="submit" class="btn btn-primary">{{call .T "notify_save_pref"}}</button>
        </div>
      </form>
    </div>

    <script nonce="{{.CSPNonce}}">
    document.querySelectorAll('.confirm-submit').forEach(function(btn){
      btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});
    });
    document.querySelectorAll('.banner-success').forEach(function(el){
      setTimeout(function(){el.style.transition='opacity 0.4s';el.style.opacity='0';setTimeout(function(){el.remove()},500)},5000);
    });
    </script>

    {{end}}
  </main>

  <div id="remove-modal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="remove-modal-title">
    <div class="modal-box">
      <h3 id="remove-modal-title">{{call .T "remove_host_title"}}: <span id="remove-hostname-display" style="font-weight:400;color:var(--text-2)"></span></h3>
      <div class="deploy-warning-banner">
        <div class="deploy-warning-icon">⚠</div>
        <div class="deploy-warning-text">{{call .T "remove_warning"}}</div>
      </div>
      <div class="script-preview" id="remove-script-preview" style="margin-bottom:16px">
        <div class="script-preview-header" id="remove-script-toggle" role="button" tabindex="0">
          <span class="script-preview-label"><span class="script-expand-chevron">&#9654;</span>{{call .T "uninstall_script"}}</span>
          <button type="button" class="btn btn-sm" id="remove-script-copy-btn"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>{{call .T "copy"}}</button>
        </div>
        <div class="script-preview-body">
          <pre id="remove-script-content">Loading...</pre>
        </div>
      </div>
      <div id="remove-form-area">
        <div style="margin-bottom:14px">
          <label style="display:flex;align-items:center;gap:8px;font-size:0.875rem;cursor:pointer">
            <input type="checkbox" id="remove-pam" checked style="width:16px;height:16px;accent-color:var(--primary)">
            {{call .T "remove_unconfigure_pam"}}
          </label>
        </div>
        <div style="margin-bottom:14px">
          <label style="display:flex;align-items:center;gap:8px;font-size:0.875rem;cursor:pointer">
            <input type="checkbox" id="remove-files" checked style="width:16px;height:16px;accent-color:var(--primary)">
            {{call .T "remove_binary"}}
          </label>
        </div>
        <div class="modal-field" style="margin-bottom:8px">
          <label style="font-size:0.8125rem;font-weight:600;color:var(--text-2)">{{call .T "remove_ssh_optional"}}</label>
        </div>
        <div class="modal-row">
          <div class="modal-field">
            <label for="remove-ssh-user">{{call .T "deploy_ssh_user"}}</label>
            <input id="remove-ssh-user" type="text" value="root" autocomplete="off" spellcheck="false">
          </div>
          <div class="modal-field" style="max-width:90px">
            <label for="remove-port">{{call .T "deploy_port"}}</label>
            <input id="remove-port" type="number" value="22" min="1" max="65535">
          </div>
        </div>
        <div class="modal-field">
          <label>{{call .T "deploy_key"}} ({{call .T "remove_ssh_optional"}})</label>
          <div id="remove-key-empty">
            <div class="key-upload-row">
              <button type="button" class="key-action-btn" id="remove-key-paste-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>{{call .T "deploy_key_paste"}}</button>
              <button type="button" class="key-action-btn" id="remove-key-upload-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span>{{call .T "deploy_key_upload"}}</span></button>
              <input type="file" id="remove-key-file" style="display:none" accept=".pem,.key,.pub,*">
            </div>
            <div id="remove-key-invalid" style="display:none;font-size:0.813rem;color:var(--danger);margin-top:8px"></div>
          </div>
          <div id="remove-key-loaded" style="display:none">
            <div class="key-info-card">
              <div class="key-info-icon">&#10003;</div>
              <div class="key-info-text">
                <div class="key-info-type" id="remove-key-type"></div>
                <div class="key-info-fp" id="remove-key-fp"></div>
              </div>
            </div>
            <button type="button" class="key-clear-btn" id="remove-key-clear-btn">{{call .T "deploy_key_change"}}</button>
          </div>
        </div>
        <div id="remove-error" style="color:var(--danger);font-size:0.813rem;margin-top:8px;display:none"></div>
        <div class="modal-actions">
          <button type="button" class="btn" id="remove-cancel-btn">{{call .T "cancel"}}</button>
          <button type="button" class="btn btn-danger" id="remove-confirm-btn">{{call .T "remove_confirm"}}</button>
        </div>
      </div>
      <div id="remove-log-area" style="display:none">
        <div id="remove-log" class="deploy-log visible" role="log" aria-live="polite"></div>
        <div id="remove-status" class="deploy-status"></div>
        <div class="modal-actions" style="margin-top:8px">
          <button type="button" class="btn" id="remove-close-btn">{{call .T "close"}}</button>
        </div>
      </div>
    </div>
  </div>
  <script nonce="{{.CSPNonce}}">
  (function(){
  var removeModal=document.getElementById('remove-modal');
  var removeCancelBtn=document.getElementById('remove-cancel-btn');
  var removeConfirmBtn=document.getElementById('remove-confirm-btn');
  var removeCloseBtn=document.getElementById('remove-close-btn');
  var removePrivKey='';
  var removeHostname='';
  var removeScriptFetched=false;
  var removeScriptContent='';
  var removeScriptPreview=document.getElementById('remove-script-preview');
  var removeScriptToggle=document.getElementById('remove-script-toggle');
  var removeScriptCopyBtn=document.getElementById('remove-script-copy-btn');
  var removeScriptEl=document.getElementById('remove-script-content');

  function fetchRemoveScript(){
    if(removeScriptFetched) return;
    removeScriptFetched=true;
    var pam=document.getElementById('remove-pam')?document.getElementById('remove-pam').checked:true;
    var files=document.getElementById('remove-files')?document.getElementById('remove-files').checked:true;
    fetch('/api/deploy/uninstall-script?pam='+pam+'&files='+files)
      .then(function(r){if(r.status===401){window.location.href='/login';return Promise.reject('401');}return r.text();})
      .then(function(t){removeScriptContent=t;if(removeScriptEl)removeScriptEl.textContent=t;})
      .catch(function(){if(removeScriptEl)removeScriptEl.textContent='(failed to load)';});
  }
  function validateAndLoadKey(text,prefix){
    var trimmed=text.trim();
    var errEl=document.getElementById(prefix+'-key-invalid');
    errEl.style.display='none';
    if(!trimmed){errEl.textContent='Key is empty.';errEl.style.display='';return;}
    if(trimmed.indexOf('PRIVATE KEY')===-1&&trimmed.indexOf('BEGIN OPENSSH')===-1){
      errEl.textContent='Does not look like a private key.';errEl.style.display='';return;
    }
    if(prefix==='remove') removePrivKey=trimmed;
    document.getElementById(prefix+'-key-empty').style.display='none';
    document.getElementById(prefix+'-key-loaded').style.display='';
    document.getElementById(prefix+'-key-type').textContent='Private key loaded';
    document.getElementById(prefix+'-key-fp').textContent='';
  }

  if(removeScriptToggle){
    removeScriptToggle.addEventListener('click',function(e){
      if(removeScriptCopyBtn&&(e.target===removeScriptCopyBtn||removeScriptCopyBtn.contains(e.target))) return;
      removeScriptPreview.classList.toggle('open');
      if(removeScriptPreview.classList.contains('open')) fetchRemoveScript();
    });
    removeScriptToggle.addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();removeScriptToggle.click();}});
  }
  if(removeScriptCopyBtn){
    removeScriptCopyBtn.addEventListener('click',function(e){
      e.stopPropagation();
      fetchRemoveScript();
      setTimeout(function(){
        var text=removeScriptContent||(removeScriptEl?removeScriptEl.textContent:'');
        if(!text) return;
        var orig=removeScriptCopyBtn.innerHTML;
        navigator.clipboard.writeText(text).then(function(){
          removeScriptCopyBtn.innerHTML='&#10003; Copied';
          setTimeout(function(){removeScriptCopyBtn.innerHTML=orig;},2000);
        }).catch(function(){});
      },removeScriptContent?0:600);
    });
  }
  document.querySelectorAll('.remove-host-btn').forEach(function(btn){
    btn.addEventListener('click',function(){
      removeHostname=btn.getAttribute('data-hostname');
      var dispEl=document.getElementById('remove-hostname-display');
      if(dispEl) dispEl.textContent=removeHostname;
      document.getElementById('remove-form-area').style.display='';
      document.getElementById('remove-log-area').style.display='none';
      document.getElementById('remove-error').style.display='none';
      removePrivKey='';
      document.getElementById('remove-key-empty').style.display='';
      document.getElementById('remove-key-loaded').style.display='none';
      removeScriptFetched=false;
      removeScriptContent='';
      if(removeScriptPreview) removeScriptPreview.classList.remove('open');
      if(removeScriptEl) removeScriptEl.textContent='Loading...';
      removeModal.classList.add('open');
    });
  });
  if(removeCancelBtn) removeCancelBtn.addEventListener('click',function(){removeModal.classList.remove('open');});
  var removePasteBtn=document.getElementById('remove-key-paste-btn');
  if(removePasteBtn){
    removePasteBtn.addEventListener('click',function(){
      navigator.clipboard.readText().then(function(text){validateAndLoadKey(text,'remove');})
        .catch(function(){
          document.getElementById('remove-key-invalid').textContent='Clipboard read failed \u2014 try uploading instead.';
          document.getElementById('remove-key-invalid').style.display='';
        });
    });
  }
  var removeKeyUploadBtn=document.getElementById('remove-key-upload-btn');
  if(removeKeyUploadBtn){
    removeKeyUploadBtn.addEventListener('click',function(){document.getElementById('remove-key-file').click();});
  }
  var removeKeyFile=document.getElementById('remove-key-file');
  if(removeKeyFile){
    removeKeyFile.addEventListener('change',function(){
      var file=removeKeyFile.files[0];
      if(!file) return;
      var reader=new FileReader();
      reader.onload=function(e){validateAndLoadKey(e.target.result,'remove');};
      reader.readAsText(file);
    });
  }
  var removeKeyClearBtn=document.getElementById('remove-key-clear-btn');
  if(removeKeyClearBtn){
    removeKeyClearBtn.addEventListener('click',function(){
      removePrivKey='';
      document.getElementById('remove-key-empty').style.display='';
      document.getElementById('remove-key-loaded').style.display='none';
    });
  }
  if(removeConfirmBtn){
    removeConfirmBtn.addEventListener('click',function(){
      var unconfigPAM=document.getElementById('remove-pam').checked;
      var removeFiles=document.getElementById('remove-files').checked;
      var errEl=document.getElementById('remove-error');
      errEl.style.display='none';
      var payload={hostname:removeHostname};
      if(removePrivKey){
        payload.private_key=removePrivKey;
        payload.ssh_user=document.getElementById('remove-ssh-user').value.trim()||'root';
        payload.port=parseInt(document.getElementById('remove-port').value)||22;
        payload.unconfigure_pam=unconfigPAM;
        payload.remove_files=removeFiles;
        removeConfirmBtn.disabled=true;
        removeConfirmBtn.textContent='Removing\u2026';
        fetch('/api/deploy/remove',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_csrf),body:JSON.stringify(payload)})
          .then(function(r){if(r.status===401){window.location.href='/login';return Promise.reject('401');}if(!r.ok)return r.text().then(function(t){throw new Error(t);});return r.json();})
          .then(function(data){
            document.getElementById('remove-form-area').style.display='none';
            document.getElementById('remove-log-area').style.display='';
            var logEl=document.getElementById('remove-log');
            var statusEl=document.getElementById('remove-status');
            var es=new EventSource('/api/deploy/stream/'+data.id);
            var _removeUnload=function(){es.close();};
            window.addEventListener('beforeunload',_removeUnload);
            es.addEventListener('message',function(e){logEl.textContent+=e.data+'\n';logEl.scrollTop=logEl.scrollHeight;});
            es.addEventListener('status',function(e){
              es.close();
              window.removeEventListener('beforeunload',_removeUnload);
              removeCloseBtn.setAttribute('data-reload','1');
              if(e.data==='done'){statusEl.textContent='\u2713 Host removed successfully.';statusEl.className='deploy-status ok';}
              else{statusEl.textContent='\u2717 Removal failed.';statusEl.className='deploy-status err';}
            });
            es.onerror=function(){es.close();window.removeEventListener('beforeunload',_removeUnload);if(!statusEl.textContent){statusEl.textContent='Connection lost.';statusEl.className='deploy-status err';}};
          })
          .catch(function(err){
            removeConfirmBtn.disabled=false;
            removeConfirmBtn.textContent='Remove';
            errEl.textContent=err.message||'Request failed.';
            errEl.style.display='';
          });
      } else {
        removeConfirmBtn.disabled=true;
        removeConfirmBtn.textContent='Removing\u2026';
        fetch('/api/hosts/remove-host',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_csrf),body:JSON.stringify(payload)})
          .then(function(r){if(r.status===401){window.location.href='/login';return Promise.reject('401');}if(!r.ok)return r.text().then(function(t){throw new Error(t);});return r.json();})
          .then(function(){
            document.getElementById('remove-form-area').style.display='none';
            document.getElementById('remove-log-area').style.display='';
            var statusEl=document.getElementById('remove-status');
            statusEl.textContent='\u2713 Host removed successfully.';
            statusEl.className='deploy-status ok';
            var closeBtn=document.getElementById('remove-close-btn');
            if(closeBtn) closeBtn.setAttribute('data-reload','1');
          })
          .catch(function(err){
            removeConfirmBtn.disabled=false;
            removeConfirmBtn.textContent='{{call .T "remove_confirm"}}';
            errEl.textContent=err.message||'Request failed.';errEl.style.display='';
          });
      }
    });
  }
  if(removeCloseBtn){
    removeCloseBtn.addEventListener('click',function(){
      removeModal.classList.remove('open');
      if(removeCloseBtn.getAttribute('data-reload')==='1') location.reload();
    });
  }
  // Focus trap for remove modal (L9)
  if(removeModal){
    removeModal.addEventListener('keydown',function(e){
      if(e.key!=='Tab')return;
      var focusable=Array.from(removeModal.querySelectorAll('button,input,select,textarea,[tabindex="0"]')).filter(function(el){return !el.disabled&&el.offsetParent!==null;});
      if(!focusable.length){e.preventDefault();return;}
      var first=focusable[0],last=focusable[focusable.length-1];
      if(e.shiftKey){if(document.activeElement===first){e.preventDefault();last.focus();}}
      else{if(document.activeElement===last){e.preventDefault();first.focus();}}
    });
  }
  // Focus trap for deploy modal (L9)
  var deployModalEl=document.getElementById('deploy-modal');
  if(deployModalEl){
    deployModalEl.addEventListener('keydown',function(e){
      if(e.key!=='Tab')return;
      var focusable=Array.from(deployModalEl.querySelectorAll('button,input,select,textarea,[tabindex="0"]')).filter(function(el){return !el.disabled&&el.offsetParent!==null;});
      if(!focusable.length){e.preventDefault();return;}
      var first=focusable[0],last=focusable[focusable.length-1];
      if(e.shiftKey){if(document.activeElement===first){e.preventDefault();last.focus();}}
      else{if(document.activeElement===last){e.preventDefault();first.focus();}}
    });
  }
  })();
  </script>

  {{if .DeployEnabled}}
  <div id="deploy-modal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="deploy-modal-title">
    <div class="modal-box">
      <h3 id="deploy-modal-title">{{call .T "deploy_modal_title"}}</h3>
      <div class="deploy-warning-banner">
        <div class="deploy-warning-icon">⚠</div>
        <div class="deploy-warning-text">
          This will SSH into the target host and install the identree PAM client, overwriting any existing configuration. The host will immediately require Pocket ID approval for all sudo commands. Ensure the host is accessible and that you have reviewed the sudo rules before proceeding.
        </div>
      </div>
      <div class="script-preview" id="deploy-script-preview">
        <div class="script-preview-header" id="deploy-script-toggle" role="button" tabindex="0">
          <span class="script-preview-label"><span class="script-expand-chevron">&#9654;</span>{{call .T "install_script"}}</span>
          <button type="button" class="btn btn-sm" id="deploy-script-copy-btn" data-cmd="curl -fsSL {{.InstallURL}}/install.sh | sudo bash"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button>
        </div>
        <div class="script-preview-body">
          <pre id="deploy-script-content">Loading...</pre>
        </div>
      </div>
      <div style="margin-bottom:14px">
        <div style="font-size:0.75rem;font-weight:600;color:var(--text-3);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:6px">{{call .T "manual_download"}}</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <a href="{{.InstallURL}}/download/identree-linux-amd64" download class="btn btn-sm"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>linux/amd64</a>
          <a href="{{.InstallURL}}/download/identree-linux-arm64" download class="btn btn-sm"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>linux/arm64</a>
        </div>
      </div>
      <div id="deploy-form-area">
        <div class="modal-row">
          <div class="modal-field">
            <label for="deploy-host">{{call .T "deploy_host"}}</label>
            <input id="deploy-host" type="text" placeholder="192.168.1.10" autocomplete="off" spellcheck="false">
          </div>
          <div class="modal-field" style="max-width:90px">
            <label for="deploy-port">{{call .T "deploy_port"}}</label>
            <input id="deploy-port" type="number" value="22" min="1" max="65535">
          </div>
        </div>
        <div class="modal-row">
          <div class="modal-field">
            <label for="deploy-ssh-user">{{call .T "deploy_ssh_user"}}</label>
            <input id="deploy-ssh-user" type="text" value="root" autocomplete="off" spellcheck="false">
          </div>
          <div class="modal-field">
            <label for="deploy-pocketid-user">{{call .T "idp_user"}}</label>
            <select id="deploy-pocketid-user">
              <option value="">{{call .T "deploy_user_loading"}}</option>
            </select>
          </div>
        </div>
        <div id="deploy-user-keys" style="display:none;margin-bottom:10px">
          <div class="deploy-user-keys-label">SSH public keys on file for this user:</div>
          <ul id="deploy-user-keys-list" class="deploy-user-keys-list"></ul>
        </div>
        <div class="modal-field">
          <label>{{call .T "deploy_key"}}</label>
          <div id="deploy-key-empty">
            <div class="key-upload-row">
              <button type="button" class="key-action-btn" id="deploy-key-paste-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>{{call .T "deploy_key_paste"}}</button>
              <button type="button" class="key-action-btn" id="deploy-key-upload-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span>{{call .T "deploy_key_upload"}}</span></button>
              <input type="file" id="deploy-key-file" style="display:none" accept=".pem,.key,.pub,*">
            </div>
            <div id="deploy-key-validating" style="display:none;font-size:0.813rem;color:var(--text-2);margin-top:8px">{{call .T "deploy_key_validating"}}</div>
            <div id="deploy-key-invalid" style="display:none;font-size:0.813rem;color:var(--danger);margin-top:8px"></div>
          </div>
          <div id="deploy-key-loaded" style="display:none">
            <div class="key-info-card">
              <div class="key-info-icon">&#10003;</div>
              <div class="key-info-text">
                <div class="key-info-type" id="deploy-key-type"></div>
                <div class="key-info-fp" id="deploy-key-fp"></div>
              </div>
            </div>
            <button type="button" class="key-clear-btn" id="deploy-key-clear-btn">{{call .T "deploy_key_change"}}</button>
          </div>
        </div>
        <div id="deploy-error" style="color:var(--danger);font-size:0.813rem;margin-top:8px;display:none"></div>
        <div class="modal-actions">
          <button type="button" class="btn" id="deploy-cancel-btn">{{call .T "cancel"}}</button>
          <button type="button" class="btn btn-primary" id="deploy-submit-btn" disabled>{{call .T "deploy_run"}}</button>
        </div>
      </div>
      <div id="deploy-log-area" style="display:none">
        <div id="deploy-log" class="deploy-log visible" role="log" aria-live="polite" aria-label="{{call .T "deploy_title"}}"></div>
        <div id="deploy-status" class="deploy-status"></div>
        <div class="modal-actions" style="margin-top:8px">
          <button type="button" class="btn" id="deploy-close-btn">{{call .T "close"}}</button>
        </div>
      </div>
    </div>
  </div>
  {{end}}
</body>
</html>`

const accessPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{call .T "access"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 28 28' fill='none'%3E%3Ccircle cx='14' cy='5' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='8.5' x2='14' y2='13' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='7' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Cline x1='14' y1='13' x2='21' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='7' cy='21' r='3.5' fill='%23a855f7'/%3E%3Ccircle cx='21' cy='21' r='3.5' fill='%23a855f7'/%3E%3Cline x1='14' y1='13' x2='14' y2='18' stroke='%23a855f7' stroke-width='2'/%3E%3Ccircle cx='14' cy='21' r='3.5' fill='%23a855f7'/%3E%3C/svg%3E">
  <style>` + sharedCSS + navCSS + `
    .access-table { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .access-table-header { display: grid; grid-template-columns: 200px 2fr 1.2fr 210px; gap: 0; padding: 8px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .access-table-filter { display: grid; grid-template-columns: 200px 2fr 1.2fr 210px; gap: 0; padding: 5px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
    .access-table-header .gtcol { align-items: center; }
    .access-table-row { display: grid; grid-template-columns: 200px 2fr 1.2fr 210px; gap: 0; padding: 10px 12px; border-bottom: 1px solid var(--border); align-items: center; }
    .access-table-row:last-child { border-bottom: none; }
    .access-table-row:hover { background: var(--surface-2); }
    .access-table--admin .access-table-header,
    .access-table--admin .access-table-filter,
    .access-table--admin .access-user-row { grid-template-columns: 200px 1.8fr 1.6fr 36px; }
    .access-user-group { border-bottom: 1px solid var(--border); }
    .access-user-group:last-child { border-bottom: none; }
    .access-user-group.expanded > .access-user-row { background: var(--primary-sub); border-bottom: 1px solid rgba(124,58,237,0.2); }
    .access-user-group.expanded > .access-user-row .access-expand-icon { color: var(--primary); }
    .access-user-row { display: grid; gap: 0; padding: 10px 12px; align-items: center; cursor: pointer; }
    .access-user-row:hover { background: var(--surface-2); }
    .access-expand-icon { display: flex; align-items: center; justify-content: flex-end; color: var(--text-3); transition: transform 0.15s; user-select: none; }
    .access-user-group.expanded .access-expand-icon { transform: rotate(90deg); }
    .access-host-rows { display: none; border-top: 1px solid var(--border); }
    .access-user-group.expanded .access-host-rows { display: block; }
    .access-host-row { display: grid; grid-template-columns: 260px 1fr 220px; gap: 0; padding: 8px 12px 8px 24px; border-bottom: 1px solid var(--border); align-items: center; background: var(--surface-2); }
    .access-host-row > div { min-width: 0; }
    .access-host-row:last-child { border-bottom: none; }
    .access-host-row:hover { background: var(--bg); }
    .access-active-count { display: inline-flex; align-items: center; justify-content: center; min-width: 20px; height: 20px; padding: 0 6px; border-radius: 10px; background: var(--primary-sub); color: var(--primary); font-size: 0.75rem; font-weight: 600; }
    .access-host-count { font-size: 0.8125rem; color: var(--text-2); }
    .access-status-pill { display: inline-flex; align-items: center; gap: 3px; background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); border-radius: 6px; padding: 2px 8px; font-size: 0.8125rem; font-weight: 500; white-space: nowrap; }
    .access-status-time { font-weight: 400; color: var(--text-2); font-size: 0.75rem; }
    .access-host-header { display: grid; grid-template-columns: 260px 1fr 220px; gap: 0; padding: 5px 12px 5px 24px; background: var(--bg); border-bottom: 1px solid var(--border); }
    .access-host-header > div { font-size: 0.75rem; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.04em; }
    .saction-btn { display: inline-flex; align-items: center; gap: 5px; padding: 5px 11px; border-radius: 6px; font-size: 0.8125rem; font-weight: 500; border: 1px solid var(--border); background: var(--surface); color: var(--text-2); cursor: pointer; transition: background 0.15s, color 0.15s, border-color 0.15s; line-height: 1.4; white-space: nowrap; }
    .saction-btn:hover { background: var(--surface-2); color: var(--text); border-color: var(--text-3); }
    .saction-btn.saction-danger { color: var(--danger); }
    .saction-btn.saction-danger:hover { background: rgba(220,53,69,0.08); border-color: var(--danger); }
    .saction-btn.saction-primary { color: var(--primary); }
    .saction-btn.saction-primary:hover { background: var(--primary-sub); border-color: rgba(124,58,237,0.4); }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    document.querySelectorAll('.banner-success').forEach(function(el){
      setTimeout(function(){el.style.transition='opacity 0.4s';el.style.opacity='0';setTimeout(function(){el.style.display='none';},400);},5000);
    });
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    document.querySelectorAll('.user-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var open=btn.classList.contains('open');
        document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});
        if(!open){btn.classList.add('open');btn.setAttribute('aria-expanded','true');}
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){document.querySelectorAll('.user-btn').forEach(function(b){b.classList.remove('open');b.setAttribute('aria-expanded','false');});});
    (function(){
      var accessJustMeActive=false,accessMyUsername='';
      var accessActiveOnlyActive=false;
      var accessPage=1,accessPs={{.DefaultPageSize}};
      function renderAccessPager(vis){
        var bar=document.getElementById('access-pagination');
        if(!bar)return;
        var total=vis.length,totalPages=Math.max(1,Math.ceil(total/accessPs));
        if(accessPage>totalPages)accessPage=1;
        var start=(accessPage-1)*accessPs;
        var isGrouped=document.querySelectorAll('#access-table .access-user-group').length>0;
        var allEls=isGrouped?Array.from(document.querySelectorAll('#access-table .access-user-group')):Array.from(document.querySelectorAll('#access-table .access-table-row'));
        allEls.forEach(function(r){r.style.display='none';});
        vis.slice(start,start+accessPs).forEach(function(r){r.style.display='';});
        if(totalPages<=1&&total>0){bar.innerHTML='';vis.forEach(function(r){r.style.display='';});return;}
        if(total===0){bar.innerHTML='';return;}
        bar.innerHTML='<button class="pagination-btn" '+(accessPage<=1?'disabled':'')+'>&#8592;</button><span class="pagination-info">'+(start+1)+'&#8211;'+Math.min(start+accessPs,total)+' of '+total+'</span><button class="pagination-btn" '+(accessPage>=totalPages?'disabled':'')+'>&#8594;</button><select class="pagination-size-select">'+[15,30,50,100].map(function(n){return'<option value="'+n+'"'+(n===accessPs?' selected':'')+'>'+n+' per page</option>';}).join('')+'</select>';
        var btns=bar.querySelectorAll('.pagination-btn');
        if(!btns[0].disabled)btns[0].addEventListener('click',function(){accessPage--;filterAccess();});
        if(!btns[1].disabled)btns[1].addEventListener('click',function(){accessPage++;filterAccess();});
        bar.querySelector('.pagination-size-select').addEventListener('change',function(){accessPs=parseInt(this.value);accessPage=1;filterAccess();});
      }
      function filterAccess(){
        var filters={};
        document.querySelectorAll('#access-table .gtcol-filter-input').forEach(function(inp){filters[inp.dataset.col]=inp.value.toLowerCase().trim();});
        var groups=Array.from(document.querySelectorAll('#access-table .access-user-group'));
        if(groups.length){
          var vis=groups.filter(function(grp){
            var uname=(grp.dataset.username||'').toLowerCase();
            if(filters.auser&&uname.indexOf(filters.auser)===-1)return false;
            if(filters.ahosts){var hn=(grp.dataset.hostnames||'').toLowerCase();if(hn.indexOf(filters.ahosts)===-1)return false;}
            if(accessJustMeActive&&accessMyUsername&&uname!==accessMyUsername.toLowerCase())return false;
            if(accessActiveOnlyActive&&!parseInt(grp.dataset.activeCount||'0'))return false;
            return true;
          });
          renderAccessPager(vis);
        } else {
          var allRows=Array.from(document.querySelectorAll('#access-table .access-table-row'));
          var vis=allRows.filter(function(row){
            for(var col in filters){if(!filters[col])continue;var cell=row.querySelector('.gtcol-'+col);if(cell&&cell.textContent.toLowerCase().indexOf(filters[col])===-1){return false;}}
            if(accessActiveOnlyActive&&row.dataset.active!=='1')return false;
            return true;
          });
          renderAccessPager(vis);
        }
      }
      document.querySelectorAll('#access-table .gtcol-filter-input').forEach(function(inp){inp.addEventListener('input',function(){accessPage=1;filterAccess();});});
      // Expand/collapse user groups
      document.querySelectorAll('.access-user-row').forEach(function(row){
        row.addEventListener('click',function(){
          var grp=row.closest('.access-user-group');
          if(grp){grp.classList.toggle('expanded');
            // Run pill overflow for newly visible cells
            grp.querySelectorAll('.access-host-rows .pill-cell').forEach(function(cell){
              var items=Array.from(cell.querySelectorAll('.pill,.group-badge'));
              if(!items.length)return;
              items.forEach(function(it){it.style.display='';});
              var ex=cell.querySelector('.pill-more-btn');if(ex)ex.remove();
              var maxShow=Math.min(items.length,4);
              for(var i=maxShow;i<items.length;i++){items[i].style.display='none';}
              while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){maxShow--;items[maxShow].style.display='none';}
              var hidden=items.length-maxShow;
              if(hidden>0){var btn=document.createElement('button');btn.className='pill-more-btn';btn.type='button';btn.textContent='+'+hidden+' more';btn.addEventListener('click',function(e){e.stopPropagation();items.forEach(function(it){it.style.display='';});cell.style.flexWrap='wrap';btn.remove();});cell.appendChild(btn);while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){items[maxShow-1].style.display='none';maxShow--;hidden++;btn.textContent='+'+hidden+' more';}}
            });
          }
        });
      });
      // Pre-populate user filter + auto-expand matching group
      var at=document.getElementById('access-table');
      if(at&&at.dataset.prefilterUser){
        var ui=at.querySelector('.gtcol-filter-input[data-col="auser"]');if(ui){ui.value=at.dataset.prefilterUser;}
        var grp=at.querySelector('.access-user-group[data-username="'+at.dataset.prefilterUser+'"]');
        if(grp)grp.classList.add('expanded');
        filterAccess();
        var afr=document.getElementById('access-admin-filter-row');var aft=document.getElementById('access-admin-filter-toggle');
        if(afr){afr.style.display='';if(aft)aft.classList.add('active');}
      }
      var ajmt=document.getElementById('access-just-me-toggle');
      if(ajmt){
        accessMyUsername=ajmt.dataset.username||'';
        function toggleAccessJM(){
          accessJustMeActive=!accessJustMeActive;
          ajmt.classList.toggle('active',accessJustMeActive);
          ajmt.setAttribute('aria-checked',accessJustMeActive?'true':'false');
          accessPage=1;
          filterAccess();
          if(accessJustMeActive&&accessMyUsername){
            var grp=document.querySelector('.access-user-group[data-username="'+accessMyUsername+'"]');
            if(grp&&!grp.classList.contains('expanded')){
              grp.classList.add('expanded');
              grp.querySelectorAll('.access-host-rows .pill-cell').forEach(function(cell){
                var items=Array.from(cell.querySelectorAll('.pill,.group-badge'));
                if(!items.length)return;
                items.forEach(function(it){it.style.display='';});
                var ex=cell.querySelector('.pill-more-btn');if(ex)ex.remove();
                var maxShow=Math.min(items.length,4);
                for(var i=maxShow;i<items.length;i++){items[i].style.display='none';}
                while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){maxShow--;items[maxShow].style.display='none';}
                var hidden=items.length-maxShow;
                if(hidden>0){var btn=document.createElement('button');btn.className='pill-more-btn';btn.type='button';btn.textContent='+'+hidden+' more';btn.addEventListener('click',function(e){e.stopPropagation();items.forEach(function(it){it.style.display='';});cell.style.flexWrap='wrap';btn.remove();});cell.appendChild(btn);while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){items[maxShow-1].style.display='none';maxShow--;hidden++;btn.textContent='+'+hidden+' more';}}
              });
            }
          }
        }
        ajmt.addEventListener('click',toggleAccessJM);
        ajmt.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleAccessJM();}});
      }
      var aaot=document.getElementById('access-active-only-toggle');
      if(aaot){
        function toggleAAO(){accessActiveOnlyActive=!accessActiveOnlyActive;aaot.classList.toggle('active',accessActiveOnlyActive);aaot.setAttribute('aria-checked',accessActiveOnlyActive?'true':'false');accessPage=1;filterAccess();}
        aaot.addEventListener('click',toggleAAO);
        aaot.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleAAO();}});
      }
      var aac=document.getElementById('access-admin-clear');
      if(aac)aac.addEventListener('click',function(){
        document.querySelectorAll('#access-table .gtcol-filter-input').forEach(function(i){i.value='';});
        accessPage=1;
        filterAccess();
      });
      (function(){var ftb=document.getElementById('access-admin-filter-toggle');var ftr=document.getElementById('access-admin-filter-row');if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      (function(){var ftb=document.getElementById('access-user-filter-toggle');var ftr=document.getElementById('access-user-filter-row');if(ftb&&ftr)ftb.addEventListener('click',function(){var shown=ftr.style.display!=='none';ftr.style.display=shown?'none':'';ftb.classList.toggle('active',!shown);if(!shown){var fi=ftr.querySelector('.gtcol-filter-input');if(fi)fi.focus();}});})();
      filterAccess();
      document.querySelectorAll('.access-saction-confirm').forEach(function(btn){btn.addEventListener('click',function(e){if(!confirm(btn.dataset.confirm)){e.preventDefault();}});});
      document.querySelectorAll('.elevate-toggle').forEach(function(btn){
        btn.addEventListener('click',function(e){e.stopPropagation();var m=btn.parentElement.querySelector('.elevate-menu');var open=m.classList.contains('open');document.querySelectorAll('.elevate-menu.open').forEach(function(x){x.classList.remove('open');});if(!open){var r=btn.getBoundingClientRect();m.style.top=(r.bottom+4)+'px';m.style.right=(window.innerWidth-r.right)+'px';m.style.left='auto';m.classList.add('open');}});
      });
      document.querySelectorAll('.pill-cell').forEach(function(cell){
        var items=Array.from(cell.querySelectorAll('.pill,.group-badge'));
        if(!items.length)return;
        items.forEach(function(it){it.style.display='';});
        var ex=cell.querySelector('.pill-more-btn');if(ex)ex.remove();
        var maxShow=Math.min(items.length,4);
        for(var i=maxShow;i<items.length;i++){items[i].style.display='none';}
        while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){maxShow--;items[maxShow].style.display='none';}
        var hidden=items.length-maxShow;
        if(hidden>0){var btn=document.createElement('button');btn.className='pill-more-btn';btn.type='button';btn.textContent='+'+hidden+' more';btn.addEventListener('click',function(){items.forEach(function(it){it.style.display='';});cell.style.flexWrap='wrap';btn.remove();});cell.appendChild(btn);while(maxShow>1&&cell.scrollWidth>cell.offsetWidth+2){items[maxShow-1].style.display='none';maxShow--;hidden++;btn.textContent='+'+hidden+' more';}}
      });
    })();
    document.addEventListener('click',function(){document.querySelectorAll('.elevate-menu.open').forEach(function(m){m.classList.remove('open');});});
  });
  </script>
</head>
<body class="app{{if .Pending}} has-pending{{end}}">
  <a href="#main-content" class="skip-link">{{call .T "skip_to_content"}}</a>` + pendingBarHTML + `
  <nav class="sidebar" aria-label="Main navigation">
    <div class="sidebar-brand">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 28 28" fill="none" aria-hidden="true"><circle cx="14" cy="5" r="3.5" fill="currentColor"/><line x1="14" y1="8.5" x2="14" y2="13" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="7" y2="18" stroke="currentColor" stroke-width="2"/><line x1="14" y1="13" x2="21" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="21" r="3.5" fill="currentColor"/><circle cx="21" cy="21" r="3.5" fill="currentColor"/><line x1="14" y1="13" x2="14" y2="18" stroke="currentColor" stroke-width="2"/><circle cx="14" cy="21" r="3.5" fill="currentColor"/></svg>
      {{call .T "app_name"}}
    </div>
    <div class="sidebar-nav">` + sidebarNavHTML + `
    </div>
    <div class="sidebar-footer">
      <div class="user-btn" tabindex="0" role="button" aria-label="{{call .T "aria_user_menu"}}" aria-haspopup="true" aria-expanded="false">
        <div class="user-avatar">{{if .Avatar}}<img src="{{.Avatar}}" alt="">{{else}}{{.Initial}}{{end}}</div>
        <div class="user-name-wrap"><span class="user-display-name">{{.Username}}{{if .IsAdmin}}<span class="user-role-badge">{{call .T "admin"}}</span>{{end}}</span></div>
        <div class="user-dropdown">
          <div class="user-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/access"><select name="lang" class="lang-select" aria-label="{{call .T "language"}}">{{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}</select></form>
          <div class="user-dropdown-divider"></div>
          <div class="user-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-opts">
            <a href="/theme?set=system&from=/access" class="theme-opt{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/access" class="theme-opt{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/access" class="theme-opt{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="user-dropdown-divider"></div>
          <form method="POST" action="/signout" style="display:inline;margin:0"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="csrf_ts" value="{{.CSRFTs}}"><button type="submit" class="user-dropdown-item" style="width:100%;text-align:left;background:none;border:none;cursor:pointer;color:var(--danger);font:inherit;font-size:0.8125rem;font-weight:500;padding:7px 14px">{{call .T "sign_out"}}</button></form>
        </div>
      </div>
    </div>
  </nav>
  <main class="main" id="main-content">
    <h1 class="sr-only">{{call .T "access"}} - {{call .T "app_name"}}</h1>
    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}

    {{if and .IsAdmin .AllPendingQueue}}
    <div class="pending-table pending-table--admin" style="margin-bottom:20px" role="table" aria-label="{{call .T "pending_requests"}}">
      <div class="pending-table-header" role="row"><div role="columnheader">{{call .T "user"}}</div><div role="columnheader">{{call .T "host"}}</div><div role="columnheader">{{call .T "code"}}</div><div role="columnheader">{{call .T "expires_in"}}</div><div role="columnheader" style="text-align:right">{{call .T "action"}}</div></div>
      {{range .AllPendingQueue}}
      <div class="pending-table-row" role="row">
        <div role="cell"><span class="pill user">{{.Username}}</span></div>
        <div role="cell"><a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a>{{if .Reason}}<span class="challenge-reason" style="display:block;font-size:0.75rem;color:var(--text-2);font-style:italic;margin-top:2px">"{{.Reason}}"</span>{{end}}</div>
        <div role="cell"><span class="code">{{.Code}}</span></div>
        <div role="cell">{{.ExpiresIn}}</div>
        <div role="cell" style="text-align:right;display:flex;gap:6px;justify-content:flex-end">
          <form method="POST" action="/api/challenges/approve" class="saction-form" style="display:flex;align-items:center;gap:4px">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="text" name="reason" maxlength="500" placeholder="{{call $.T "reason_optional"}}" style="font-size:0.75rem;padding:3px 7px;border:1px solid var(--border);border-radius:5px;background:var(--surface);color:var(--text);width:120px">
            <button type="submit" class="saction-btn saction-btn--approve">{{call $.T "approve"}}</button>
          </form>
          <form method="POST" action="/api/challenges/reject" class="saction-form">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <button type="submit" class="saction-btn saction-btn--deny access-saction-confirm" data-confirm="{{call $.T "confirm_reject_all"}}">{{call $.T "reject"}}</button>
          </form>
        </div>
      </div>
      {{end}}
    </div>
    {{end}}

    {{if .IsAdmin}}
    <div class="access-table access-table--admin" id="access-table" data-prefilter-user="{{.FilterUser}}" role="table" aria-label="{{call .T "access"}}">
      <div class="access-table-header" role="row">
        <div class="gtcol gtcol-auser" role="columnheader" style="gap:10px;align-items:center;flex-wrap:wrap"><button type="button" class="filter-toggle-btn" id="access-admin-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button><span class="col-sort-link">{{call .T "user"}}</span><div class="toggle-wrap" id="access-just-me-toggle" role="switch" aria-checked="false" tabindex="0" data-username="{{.Username}}"><span>{{call .T "just_me"}}</span><div class="toggle-track"><div class="toggle-thumb"></div></div></div></div>
        <div class="gtcol" role="columnheader"><span class="col-sort-link">{{call .T "hosts"}}</span></div>
        <div class="gtcol" role="columnheader" style="gap:10px;align-items:center;flex-wrap:wrap"><span class="col-sort-link">{{call .T "sessions"}}</span><div class="toggle-wrap" id="access-active-only-toggle" role="switch" aria-checked="false" tabindex="0"><span>{{call .T "active_only"}}</span><div class="toggle-track"><div class="toggle-thumb"></div></div></div></div>
        <div class="gtcol" role="columnheader"></div>
      </div>
      <div class="access-table-filter" id="access-admin-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="auser" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="ahosts" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div></div>
        <div style="display:flex;justify-content:flex-end;align-items:center;padding:0 6px"><button type="button" class="filter-clear-btn" id="access-admin-clear">{{call .T "clear_filter"}}</button></div>
      </div>
      {{range .AllUserGroups}}
      <div class="access-user-group" data-username="{{.Username}}" data-active-count="{{.ActiveCount}}" data-hostnames="{{range .Hosts}}{{.Hostname}} {{end}}">
        <div class="access-user-row" role="row">
          <div class="gtcol gtcol-auser" role="cell"><a href="/access?user={{.Username}}" class="pill user">{{.Username}}</a></div>
          <div class="gtcol" role="cell"><div class="pill-cell">{{range .Hosts}}<a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a>{{end}}</div></div>
          <div class="gtcol" role="cell"><div class="pill-cell">{{if .ActiveCount}}{{range .Hosts}}{{if .Active}}<a href="/?host={{.Hostname}}" class="pill host">{{.Hostname}}</a>{{end}}{{end}}{{end}}</div></div>
          <div class="gtcol" role="cell"><span class="access-expand-icon">&#9654;</span></div>
        </div>
        <div class="access-host-rows">
          <div class="access-host-header">
            <div>{{call $.T "host"}}</div>
            <div>{{call $.T "commands"}}</div>
            <div>{{call $.T "action"}}</div>
          </div>
          {{range .Hosts}}
          <div class="access-host-row">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><a href="/history?hostname={{.Hostname}}" class="pill host">{{.Hostname}}</a>{{if .Active}}<span class="access-status-pill">{{call $.T "active"}} <span class="access-status-time">({{.Remaining}})</span></span>{{end}}</div>
            <div><div class="pill-cell">{{if .AllCmds}}<span class="pill cmd">{{call $.T "all_commands"}}</span>{{else}}{{range .Commands}}<span class="pill cmd">{{.}}</span>{{end}}{{end}}</div></div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
              {{if .Active}}
              <div class="elevate-wrap">
                <button type="button" class="saction-btn saction-primary elevate-toggle"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>{{call $.T "extend"}}<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px"><polyline points="6 9 12 15 18 9"/></svg></button>
                <form method="POST" action="/api/sessions/extend" class="elevate-menu">
                  <input type="hidden" name="hostname" value="{{.Hostname}}">
                  <input type="hidden" name="username" value="{{$.Username}}">
                  <input type="hidden" name="session_username" value="{{.Username}}">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                  <input type="hidden" name="from" value="/access">
                  {{range .ExtendDurations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
                  <button type="submit" name="duration" value="max">{{call $.T "max"}}</button>
                </form>
              </div>
              <form method="POST" action="/api/sessions/revoke" style="display:inline">
                <input type="hidden" name="hostname" value="{{.Hostname}}">
                <input type="hidden" name="username" value="{{$.Username}}">
                <input type="hidden" name="session_username" value="{{.Username}}">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                <input type="hidden" name="from" value="/access">
                <button type="submit" class="saction-btn saction-danger access-saction-confirm" data-confirm="{{printf (call $.T "confirm_revoke_session_user") .Username .Hostname}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>{{call $.T "revoke"}}</button>
              </form>
              {{end}}
              {{if not .Active}}
              <div class="elevate-wrap">
                <button type="button" class="saction-btn saction-primary elevate-toggle"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>{{call $.T "elevate"}}<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px"><polyline points="6 9 12 15 18 9"/></svg></button>
                <form method="POST" action="/api/hosts/elevate" class="elevate-menu">
                  <input type="hidden" name="hostname" value="{{.Hostname}}">
                  <input type="hidden" name="username" value="{{$.Username}}">
                  <input type="hidden" name="target_user" value="{{.Username}}">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                  <input type="hidden" name="from" value="/access">
                  {{range $.Durations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
                </form>
              </div>
              {{end}}
            </div>
          </div>
          {{end}}
        </div>
      </div>
      {{end}}
      {{if not .AllUserGroups}}
      <div style="text-align:center;color:var(--text-2);font-size:0.875rem;padding:20px 0">{{call .T "no_known_hosts"}}</div>
      {{end}}
    </div>
    <div class="pagination-bar" id="access-pagination"></div>
    {{else}}
    <div class="access-table" id="access-table" role="table" aria-label="{{call .T "access"}}">
      <div class="access-table-header" role="row">
        <div class="gtcol gtcol-ahost" role="columnheader" style="gap:8px;align-items:center"><button type="button" class="filter-toggle-btn" id="access-user-filter-toggle" aria-label="Toggle filters"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></button><span class="col-sort-link">{{call .T "host"}}</span></div>
        <div class="gtcol gtcol-aperms" role="columnheader"><span class="col-sort-link">{{call .T "commands"}}</span></div>
        <div class="gtcol gtcol-asession" role="columnheader"><span class="col-sort-link">{{call .T "sessions"}}</span></div>
        <div class="gtcol gtcol-aactions" role="columnheader"><span class="col-sort-link">{{call .T "action"}}</span></div>
      </div>
      <div class="access-table-filter" id="access-user-filter-row" style="display:none">
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="ahost" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div class="gtcol-filter-wrap"><input type="text" class="gtcol-filter-input" data-col="aperms" placeholder="{{call .T "search"}}…" autocomplete="off"></div>
        <div></div>
        <div></div>
      </div>
      {{range .HostAccess}}
      <div class="access-table-row" role="row" data-active="{{if .Active}}1{{else}}0{{end}}">
        <div class="gtcol gtcol-ahost" role="cell"><div class="pill-cell"><span class="pill host">{{.Hostname}}</span></div></div>
        <div class="gtcol gtcol-aperms" role="cell">
          <div class="pill-cell">{{if .AllCmds}}<span class="pill cmd">{{call $.T "all_commands"}}</span>{{else}}{{range .Commands}}<span class="pill cmd">{{.}}</span>{{end}}{{end}}</div>
        </div>
        <div class="gtcol gtcol-asession" role="cell">
          {{if .Active}}
            <span class="access-status-pill">{{call $.T "active"}} <span class="access-status-time">({{.Remaining}})</span></span>
          {{end}}
        </div>
        <div class="gtcol gtcol-aactions" role="cell" style="gap:6px;flex-wrap:wrap;align-items:center">
          <div class="elevate-wrap">
            <button type="button" class="saction-btn saction-primary elevate-toggle"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>{{call $.T "elevate"}}<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px"><polyline points="6 9 12 15 18 9"/></svg></button>
            <form method="POST" action="/api/hosts/elevate" class="elevate-menu">
              <input type="hidden" name="hostname" value="{{.Hostname}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="target_user" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <input type="hidden" name="from" value="/access">
              {{range $.Durations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
            </form>
          </div>
        </div>
      </div>
      {{end}}
      {{if not .HostAccess}}
      <div style="text-align:center;color:var(--text-2);font-size:0.875rem;padding:20px 0">{{call .T "no_known_hosts"}}</div>
      {{end}}
    </div>
    {{end}}
  </main>
</body>
</html>`

const approvalExpiredHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
<head>
  <title>{{call .T "request_expired"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-warning {
      background: var(--warning-bg);
      border: 2px solid var(--warning-border);
      color: var(--warning);
    }
    h2 { color: var(--warning); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-warning" aria-hidden="true">&#x23f0;</div>
    <h2>{{call .T "request_expired"}}</h2>
    <p>{{call .T "request_expired_message"}}</p>
    <p>{{call .T "request_expired_action"}}</p>
  </div>
</body>
</html>`

// approvalAlreadyHTML uses html/template syntax so the status is safely escaped.
const approvalAlreadyHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
<head>
  <title>{{call .T "already_resolved"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-info {
      background: var(--info-bg);
      border: 2px solid var(--info-border);
      color: var(--primary);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-info" aria-hidden="true">&#x2139;</div>
    <h2>{{call .T "already_resolved"}}</h2>
    <p>{{printf (call .T "already_resolved_message") .Status}}</p>
  </div>
</body>
</html>`

