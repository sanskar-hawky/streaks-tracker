import csv
import json
import logging
import os
import secrets as _secrets
from datetime import date, timedelta
from threading import Thread

from authlib.integrations.flask_client import OAuth
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import config as cfg
from data import store
from data.ist import ist_now, ist_today, is_weekend, last_n_dates_ist
from data.mixpanel import MixpanelClient
from data.modules import ALL_MODULES
from data.refresh import RefreshDaemon, cleanup_hawky_events, run_refresh
from data.creatives_sync import run_creatives_sync
from data.streaks import calc_streak

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "streak-tracker-local-only"
# Behind Coolify/Fly the app sits behind a TLS-terminating reverse proxy. Trust
# the X-Forwarded-* headers so url_for(_external=True) builds https:// callback
# URLs (Google OAuth rejects http:// redirect URIs for non-localhost hosts).
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ---- Authentication ------------------------------------------------------
# Three-tier gate, highest-priority first:
#   1. Google OAuth (Option C) — when GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET
#      are set. Only @hawky.ai (GOOGLE_ALLOWED_DOMAINS) emails may enter.
#   2. HTTP Basic Auth — when STREAKS_AUTH_PASSWORD is set (legacy / simple).
#   3. Open — neither configured (local dev convenience).
_AUTH_USER = os.environ.get("STREAKS_AUTH_USER")
_AUTH_PASSWORD = os.environ.get("STREAKS_AUTH_PASSWORD")
_AUTH_REALM = 'Basic realm="streak-tracker", charset="UTF-8"'
# Endpoints reachable without a session (the login dance + health check).
_AUTH_EXEMPT_ENDPOINTS = {"healthz", "login", "auth_google", "auth_callback", "logout", "static"}
_AUTH_EXEMPT_PATHS = {"/healthz"}

oauth = OAuth(app)


def _oauth_enabled():
    return bool(cfg.GOOGLE_CLIENT_ID and cfg.GOOGLE_CLIENT_SECRET)


if _oauth_enabled():
    oauth.register(
        name="google",
        server_metadata_url=cfg.GOOGLE_DISCOVERY_URL,
        client_id=cfg.GOOGLE_CLIENT_ID,
        client_secret=cfg.GOOGLE_CLIENT_SECRET,
        client_kwargs={"scope": "openid email profile"},
    )


def _email_allowed(email):
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False
    if email in cfg.GOOGLE_ALLOWED_EMAILS:
        return True
    return email.rsplit("@", 1)[-1] in cfg.GOOGLE_ALLOWED_DOMAINS


@app.before_request
def _require_auth():
    if request.endpoint in _AUTH_EXEMPT_ENDPOINTS or request.path in _AUTH_EXEMPT_PATHS:
        return

    if _oauth_enabled():
        if session.get("user"):
            return
        # Remember where the user was headed so we can bounce them back after
        # login (GET navigations only — never replay a POST).
        if request.method == "GET":
            session["next"] = request.url
        return redirect(url_for("login"))

    # Fallback: HTTP Basic Auth.
    if not _AUTH_PASSWORD:
        return  # nothing configured → open (local dev)
    auth = request.authorization
    if (
        not auth
        or auth.type != "basic"
        or auth.username != _AUTH_USER
        or not _secrets.compare_digest(auth.password or "", _AUTH_PASSWORD)
    ):
        return Response("Auth required", 401, {"WWW-Authenticate": _AUTH_REALM})


@app.route("/login")
def login():
    if not _oauth_enabled():
        # No Google config → there's nothing to log into; send them home (the
        # Basic Auth / open gate handles access in that mode).
        return redirect(url_for("index"))
    if session.get("user"):
        return redirect(url_for("index"))
    # Render OUR branded sign-in page. The "Sign in with Google" button on it
    # points at /auth/google, which is what actually starts the OAuth redirect.
    return render_template("login.html")


@app.route("/auth/google")
def auth_google():
    if not _oauth_enabled():
        return redirect(url_for("index"))
    redirect_uri = url_for("auth_callback", _external=True)
    # `hd` nudges Google's account picker toward the org domain (single-domain
    # setups only). It's a hint, not a guarantee — we re-verify server-side.
    kwargs = {}
    if len(cfg.GOOGLE_ALLOWED_DOMAINS) == 1:
        kwargs["hd"] = next(iter(cfg.GOOGLE_ALLOWED_DOMAINS))
    return oauth.google.authorize_redirect(redirect_uri, **kwargs)


@app.route("/auth/callback")
def auth_callback():
    if not _oauth_enabled():
        return redirect(url_for("index"))
    try:
        token = oauth.google.authorize_access_token()
    except Exception:
        log.exception("OAuth token exchange failed")
        return render_template("login.html", error="Sign-in failed. Please try again."), 400
    userinfo = token.get("userinfo") or {}
    email = (userinfo.get("email") or "").strip().lower()
    if not userinfo.get("email_verified", False) or not _email_allowed(email):
        session.pop("user", None)
        allowed = ", ".join(sorted(cfg.GOOGLE_ALLOWED_DOMAINS)) or "an authorized"
        return render_template(
            "login.html",
            error=f"{email or 'That account'} isn't allowed. Sign in with your @{allowed} account.",
        ), 403
    session["user"] = {
        "email": email,
        "name": userinfo.get("name"),
        "picture": userinfo.get("picture"),
    }
    session.permanent = True
    dest = session.pop("next", None) or url_for("index")
    return redirect(dest)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login") if _oauth_enabled() else url_for("index"))


@app.route("/healthz")
def healthz():
    """Public, unauthenticated. Fly's HTTP healthcheck pings this."""
    return {"ok": True}, 200

mp_client = MixpanelClient(
    cfg.MIXPANEL_PROJECT_ID,
    cfg.MIXPANEL_USERNAME,
    cfg.MIXPANEL_SECRET,
    cfg.EXPORT_URL,
    cfg.ENGAGE_URL,
)

# Hawky-managed names known to be agencies (vs parent companies).
KNOWN_AGENCIES = {
    "Social Beat", "HiveMinds", "367 Agency", "Interactive Avenue", "88GB",
}


# -------- settings helpers ----------------------------------------------

def _get_setting(key, default):
    with store.db(cfg.DB_PATH) as conn:
        return store.get_setting(conn, key, str(default))


def _get_int_setting(key, default):
    raw = _get_setting(key, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _get_hawky_domains():
    raw = _get_setting("hawky_domains", cfg.DEFAULT_HAWKY_DOMAINS)
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def _get_hawky_substrings():
    raw = _get_setting("hawky_substrings", cfg.DEFAULT_HAWKY_SUBSTRINGS)
    return tuple(s.strip().lower() for s in raw.split(",") if s.strip())


def _get_copilot_message_event():
    raw = _get_setting("copilot_message_event", cfg.DEFAULT_COPILOT_MESSAGE_EVENT)
    return (raw or cfg.DEFAULT_COPILOT_MESSAGE_EVENT).strip()


def _get_weekend_set():
    raw = _get_setting("weekend_days", cfg.DEFAULT_WEEKEND_DAYS)
    try:
        return {int(x) for x in raw.split(",") if x.strip() != ""}
    except ValueError:
        return {5, 6}


# -------- seed loader ---------------------------------------------------

def _split_agency_parent(row):
    """
    Tolerate both forms:
      new:    agency=..., parent_company=...
      legacy: single 'agency/parent company' column (or 'agency' alone)
              → known-agency names map to agency, the rest to parent_company.
    """
    agency = (row.get("agency") or "").strip()
    parent = (row.get("parent_company") or row.get("parent company") or "").strip()
    legacy = (row.get("agency/parent company") or "").strip()
    if not agency and not parent and legacy:
        if legacy in KNOWN_AGENCIES:
            agency = legacy
        else:
            parent = legacy
    # If only the agency column is populated with a parent-company name, fix it.
    if agency and not parent and agency not in KNOWN_AGENCIES:
        parent = agency
        agency = ""
    return (agency or None), (parent or None)


def _seed_brands_if_empty():
    with store.db(cfg.DB_PATH) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM brands").fetchone()["n"]
    if n > 0 or not cfg.SEED_PATH.exists():
        return
    with open(cfg.SEED_PATH) as f, store.db(cfg.DB_PATH) as conn:
        for row in csv.DictReader(f):
            bid = (row.get("brand_id") or "").strip()
            if not bid:
                continue
            agency, parent = _split_agency_parent(row)
            store.upsert_brand(
                conn,
                brand_id=bid,
                brand_name=(row.get("brand") or row.get("brand_name") or "").strip(),
                instance_label=(row.get("instance") or "").strip() or None,
                agency=agency,
                parent_company=parent,
                is_active=1,
            )


def _seed_settings_if_empty():
    defaults = {
        "refresh_min": cfg.DEFAULT_REFRESH_MIN,
        "day_window": cfg.DEFAULT_DAY_WINDOW,
        "weekend_days": cfg.DEFAULT_WEEKEND_DAYS,
        "timezone": cfg.DEFAULT_TIMEZONE,
        "hawky_domains": cfg.DEFAULT_HAWKY_DOMAINS,
        "hawky_substrings": cfg.DEFAULT_HAWKY_SUBSTRINGS,
        "copilot_heavy": cfg.DEFAULT_COPILOT_HEAVY,
        "copilot_moderate": cfg.DEFAULT_COPILOT_MODERATE,
        "copilot_message_event": cfg.DEFAULT_COPILOT_MESSAGE_EVENT,
        "snapshot_cap": cfg.DEFAULT_SNAPSHOT_CAP,
        "product_base_url": cfg.DEFAULT_PRODUCT_BASE_URL,
    }
    with store.db(cfg.DB_PATH) as conn:
        for k, v in defaults.items():
            if store.get_setting(conn, k) is None:
                store.set_setting(conn, k, v)


# -------- index page model ----------------------------------------------

SORT_KEYS = {
    "streak":      lambda r: (r["streak"], r["events_total"]),
    "events":      lambda r: (r["events_total"], r["streak"]),
    "users":       lambda r: (r["users_total"], r["events_total"]),
    "today":       lambda r: (r["today_events"], r["events_total"]),
    "last_active": lambda r: (r["last_active"] or "0000-00-00",),
    "brand":       lambda r: (r["brand"]["brand_name"].lower(),),
}


def _build_rows(brands, agg, days, weekend, today, module_counts,
                copilot_summary=None, active_now=None):
    rows = []
    copilot_summary = copilot_summary or {}
    active_now = active_now or set()
    for b in brands:
        bid = b["brand_id"]
        per_day = agg.get(bid, {})
        active_dates_set = {date.fromisoformat(d) for d, v in per_day.items() if v["events"] > 0}
        streak = calc_streak(active_dates_set, today=today, weekend_days=weekend)
        events_total = sum(v["events"] for v in per_day.values())
        users_total = max((v["users"] for v in per_day.values()), default=0)
        today_events = per_day.get(str(today), {}).get("events", 0)
        last_active = max((d for d, v in per_day.items() if v["events"] > 0), default=None)
        # Walk back from today on weekdays to surface the streak window endpoints
        # for the tooltip. cheap, no extra DB.
        streak_dates = sorted(active_dates_set)
        # Pull only the trailing streak (consecutive run ending at last weekday).
        trailing = []
        cur = today if today in active_dates_set or is_weekend(today, weekend) else today
        # Reconstruct: iterate the same way calc_streak does, collecting dates.
        from datetime import timedelta as _td
        c = today
        if not is_weekend(c, weekend) and c not in active_dates_set:
            c = c - _td(days=1)
        safety = 0
        while safety < 400:
            safety += 1
            if is_weekend(c, weekend):
                c = c - _td(days=1)
                continue
            if c in active_dates_set:
                trailing.append(c)
                c = c - _td(days=1)
            else:
                break
        # Sparkline over the last 7 days of the window.
        spark_days = days[-7:]
        spark = [per_day.get(str(d), {}).get("events", 0) for d in spark_days]
        spark_max = max(spark) if spark else 0
        denom = spark_max or 1
        spark_points = " ".join(
            f"{i * 10},{16 - int(13 * n / denom) - 1}"
            for i, n in enumerate(spark)
        )
        day_cells = []
        for d in days:
            v = per_day.get(str(d), {"events": 0, "users": 0})
            we = is_weekend(d, weekend)
            tip = f"{d.strftime('%a · %d %b')} · {v['events']} events · {v['users']} users"
            if we:
                tip += " · weekend"
            elif d == today:
                tip += " · today"
            day_cells.append({
                "date": d.isoformat(),
                "events": v["events"],
                "users": v["users"],
                "is_weekend": we,
                "is_today": d == today,
                "tip": tip,
            })
        cp = copilot_summary.get(bid, {})
        rows.append({
            "brand": b,
            "streak": streak,
            "streak_from": trailing[-1].isoformat() if trailing else None,
            "streak_to":   trailing[0].isoformat() if trailing else None,
            "events_total": events_total,
            "users_total": users_total,
            "today_events": today_events,
            "last_active": last_active,
            "day_cells": day_cells,
            "spark": spark,
            "spark_max": spark_max,
            "spark_points": spark_points,
            "modules": module_counts.get(bid, {m: 0 for m in ALL_MODULES} | {"total": 0}),
            "copilot_msgs_7d": cp.get("week_messages", 0),
            "is_active_now": bid in active_now,
        })
    return rows


KPI_PREDICATES = {
    "active_today":    lambda r, ctx: r["today_events"] > 0,
    "active_now":      lambda r, ctx: r["is_active_now"],
    "active_period":   lambda r, ctx: r["events_total"] > 0,
    "perfect_streak":  lambda r, ctx: ctx["weekday_count"] and r["streak"] >= ctx["weekday_count"],
    "copilot_msgs_7d": lambda r, ctx: r["copilot_msgs_7d"] > 0,
}


def _apply_filters(rows, *, q, agency, parent, module, kpi=None, kpi_ctx=None):
    out = []
    qn = (q or "").strip().lower()
    pred = KPI_PREDICATES.get(kpi) if kpi else None
    ctx = kpi_ctx or {}
    for r in rows:
        b = r["brand"]
        if agency and (b.get("agency") or "") != agency:
            continue
        if parent and (b.get("parent_company") or "") != parent:
            continue
        if module and r["modules"].get(module, 0) <= 0:
            continue
        if qn and qn not in b["brand_name"].lower() and qn not in (b["brand_id"] or "").lower():
            continue
        if pred and not pred(r, ctx):
            continue
        out.append(r)
    return out


def _quantile_thresholds(values):
    """Return four thresholds (q20, q40, q60, q80) for a list of ints. Zeros are excluded."""
    nz = sorted(v for v in values if v and v > 0)
    if not nz:
        return [0, 0, 0, 0]
    n = len(nz)

    def at(p):
        return nz[min(n - 1, max(0, int(p * n) - 1))]

    return [at(0.2), at(0.4), at(0.6), at(0.8)]


# -------- routes ---------------------------------------------------------

@app.context_processor
def _inject_globals():
    with store.db(cfg.DB_PATH) as conn:
        last_run = store.latest_run(conn)
    day_window = _get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW)
    today = ist_today()
    window_from = today - timedelta(days=day_window - 1)
    return {
        "last_run": last_run,
        "ist_now": ist_now(),
        "global_day_window": day_window,
        "global_window_from": window_from,
        "global_window_to": today,
    }


@app.route("/")
def index():
    day_window = _get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW)
    weekend = _get_weekend_set()
    today = ist_today()
    ist_from = today - timedelta(days=day_window - 1)

    # Filters from URL
    f_agency = request.args.get("agency", "").strip()
    f_parent = request.args.get("parent", "").strip()
    f_module = request.args.get("module", "").strip()
    f_q      = request.args.get("q", "").strip()
    f_kpi    = request.args.get("kpi", "").strip()
    if f_kpi and f_kpi not in KPI_PREDICATES:
        f_kpi = ""
    f_sort   = request.args.get("sort", "streak")
    f_dir    = request.args.get("dir", "desc")

    msg_event = _get_copilot_message_event()
    week_from = today - timedelta(days=6)

    with store.db(cfg.DB_PATH) as conn:
        brands = store.list_brands(conn, active_only=True)
        agg = store.events_by_brand_day(conn, ist_from, today)
        module_counts = store.module_counts_by_brand(conn, ist_from, today)
        module_users = store.module_users_by_brand(conn, ist_from, today)
        metric_series = store.metric_series_by_day(conn, ist_from, today, msg_event)
        mix_total = store.module_mix_total(conn, ist_from, today)
        # rolling-24h active
        cutoff_iso = (ist_now() - timedelta(hours=24)).isoformat()
        active_now = store.active_brands_since(conn, cutoff_iso)
        # Per-brand Co-Pilot summary (powers the copilot_msgs_7d KPI filter)
        copilot_summary = store.copilot_brand_summary(conn, today, day_window, msg_event)
        # Co-Pilot messages-sent KPIs
        msgs_7d = conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT distinct_id) AS u, COUNT(DISTINCT brand_id) AS b "
            "FROM events WHERE event_name=? AND ist_date BETWEEN ? AND ?",
            (msg_event, str(week_from), str(today)),
        ).fetchone()
        msgs_window = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_name=? AND ist_date BETWEEN ? AND ?",
            (msg_event, str(ist_from), str(today)),
        ).fetchone()

    days = last_n_dates_ist(day_window, end=today)
    weekday_count = sum(1 for d in days if not is_weekend(d, weekend))

    all_rows = _build_rows(brands, agg, days, weekend, today, module_counts,
                           copilot_summary=copilot_summary, active_now=active_now)
    # KPIs from unfiltered row set so totals stay stable as filters change.
    kpis = {
        "total":            len(all_rows),
        "active_today":     sum(1 for r in all_rows if r["today_events"] > 0),
        "active_now":       sum(1 for r in all_rows if r["is_active_now"]),
        "active_period":    sum(1 for r in all_rows if r["events_total"] > 0),
        "perfect_streak":   sum(1 for r in all_rows if weekday_count and r["streak"] >= weekday_count),
        "copilot_msgs_7d":      msgs_7d["n"] or 0,
        "copilot_msg_users_7d": msgs_7d["u"] or 0,
        "copilot_msg_brands_7d": msgs_7d["b"] or 0,
        "copilot_msgs_window":   msgs_window["n"] or 0,
    }
    rows = _apply_filters(all_rows, q=f_q, agency=f_agency, parent=f_parent,
                          module=f_module, kpi=f_kpi,
                          kpi_ctx={"weekday_count": weekday_count})

    key_fn = SORT_KEYS.get(f_sort, SORT_KEYS["streak"])
    rows.sort(key=key_fn, reverse=(f_dir != "asc"))

    # When any filter is active, re-scope the engagement chart + module-mix
    # donut to only the visible brands. KPI cards stay global (they're the
    # filter controls). Matrix quantile thresholds stay global too (intentional:
    # they tell you where a brand falls relative to the full roster).
    filters_active = bool(f_q or f_agency or f_parent or f_module or f_kpi)
    chart_scope_label = ""
    if filters_active:
        visible_brand_ids = [r["brand"]["brand_id"] for r in rows]
        n = len(visible_brand_ids)
        chart_scope_label = f" · filtered to {n} brand" + ("" if n == 1 else "s")
        if visible_brand_ids:
            with store.db(cfg.DB_PATH) as conn:
                metric_series = store.metric_series_by_day(
                    conn, ist_from, today, msg_event, brand_ids=visible_brand_ids,
                )
                mix_total = store.module_mix_total(
                    conn, ist_from, today, brand_ids=visible_brand_ids,
                )
        else:
            metric_series = {}
            mix_total = {m: 0 for m in ALL_MODULES}

    # Per-module quantile thresholds for the matrix coloring.
    matrix_thresholds = {
        m: _quantile_thresholds([r["modules"][m] for r in all_rows])
        for m in ALL_MODULES
    }

    # Distinct agencies + parents for filter dropdowns
    agencies = sorted({(b.get("agency") or "") for b in brands if b.get("agency")})
    parents  = sorted({(b.get("parent_company") or "") for b in brands if b.get("parent_company")})

    # Chart series — bake all metrics so the dropdown switches instantly
    # without a round trip. Keys map to the values in <select> on /.
    cats = [d.isoformat() for d in days]

    def _series(key):
        return [metric_series.get(c, {}).get(key, 0) for c in cats]

    chart_engagement = {
        "categories": cats,
        "metrics": {
            "events":           {"label": "Events",                "data": _series("events")},
            "users":            {"label": "Users",                 "data": _series("users")},
            "brands":           {"label": "Active brands",         "data": _series("brands")},
            "copilot_messages": {"label": "Co-Pilot messages sent","data": _series("copilot_messages")},
            "copilot_events":   {"label": "Co-Pilot events (all)", "data": _series("copilot_events")},
            "copilot_users":    {"label": "Co-Pilot users",        "data": _series("copilot_users")},
        },
    }
    chart_module_mix = {
        "labels": ALL_MODULES,
        "series": [mix_total.get(m, 0) for m in ALL_MODULES],
    }

    # Precompute "clear this filter" URLs for the filter-pill row.
    def _clear(key):
        params = {"q": f_q, "agency": f_agency, "parent": f_parent, "module": f_module,
                  "kpi": f_kpi, "sort": f_sort, "dir": f_dir}
        params[key] = ""
        return url_for("index", **{k: v for k, v in params.items() if v})

    clear_urls = {k: _clear(k) for k in ("q", "agency", "parent", "module", "kpi")}

    # Pre-compute per-KPI link URLs so the cards on `/` can be coral-ringed when
    # active and "click again to clear" without messy template logic.
    def _kpi_link(name):
        params = {"q": f_q, "agency": f_agency, "parent": f_parent, "module": f_module,
                  "sort": f_sort, "dir": f_dir}
        if f_kpi != name:
            params["kpi"] = name
        return url_for("index", **{k: v for k, v in params.items() if v})

    kpi_links = {name: _kpi_link(name) for name in list(KPI_PREDICATES) + ["total"]}

    return render_template(
        "index.html",
        rows=rows, total_visible=len(rows), total_all=len(all_rows),
        kpis=kpis, days=days, day_window=day_window, weekday_count=weekday_count,
        modules=ALL_MODULES, matrix_thresholds=matrix_thresholds,
        agencies=agencies, parents=parents,
        f_agency=f_agency, f_parent=f_parent, f_module=f_module, f_q=f_q,
        f_kpi=f_kpi, kpi_links=kpi_links,
        f_sort=f_sort, f_dir=f_dir,
        chart_engagement=chart_engagement,
        chart_module_mix=chart_module_mix,
        chart_scope_label=chart_scope_label,
        module_users=module_users,
        clear_urls=clear_urls,
    )


BRAND_TABS = ["overview", "users", "sections", "pages"]
COPILOT_BUCKETS = ("heavy", "moderate", "trialing", "never")


def _copilot_bucket(week_events, heavy_th, moderate_th):
    if week_events <= 0:
        return "never"
    if week_events > heavy_th:
        return "heavy"
    if week_events > moderate_th:
        return "moderate"
    return "trialing"


@app.route("/copilot")
def copilot_page():
    f_bucket = request.args.get("bucket", "").strip().lower()
    if f_bucket not in COPILOT_BUCKETS:
        f_bucket = ""

    day_window = _get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW)
    heavy_th = _get_int_setting("copilot_heavy", cfg.DEFAULT_COPILOT_HEAVY)
    moderate_th = _get_int_setting("copilot_moderate", cfg.DEFAULT_COPILOT_MODERATE)
    today = ist_today()

    days = last_n_dates_ist(day_window, end=today)
    cats = [d.isoformat() for d in days]

    msg_event = _get_copilot_message_event()
    with store.db(cfg.DB_PATH) as conn:
        brands = store.list_brands(conn, active_only=True)
        summary = store.copilot_brand_summary(conn, today, day_window, msg_event)

    rows = []
    for b in brands:
        bid = b["brand_id"]
        s = summary.get(bid, {
            "window_events": 0, "window_users": 0,
            "week_events": 0, "week_users": 0,
            "window_messages": 0, "week_messages": 0,
            "window_message_users": 0, "week_message_users": 0,
            "last_seen": None, "last_message": None,
            "daily": {}, "daily_messages": {},
        })
        week_events = s["week_events"]
        bucket = _copilot_bucket(week_events, heavy_th, moderate_th)

        spark = [s["daily"].get(c, 0) for c in cats]
        denom = max(spark) or 1
        spark_points = " ".join(
            f"{i * 10},{16 - int(13 * n / denom) - 1}"
            for i, n in enumerate(spark)
        )
        # Second sparkline: messages-sent only (the high-signal metric)
        msg_spark = [s["daily_messages"].get(c, 0) for c in cats]
        msg_denom = max(msg_spark) or 1
        msg_spark_points = " ".join(
            f"{i * 10},{16 - int(13 * n / msg_denom) - 1}"
            for i, n in enumerate(msg_spark)
        )

        rows.append({
            "brand":           b,
            "window_events":   s["window_events"],
            "window_users":    s["window_users"],
            "week_events":     week_events,
            "week_users":      s["week_users"],
            "window_messages": s["window_messages"],
            "week_messages":   s["week_messages"],
            "window_message_users": s["window_message_users"],
            "week_message_users":   s["week_message_users"],
            "last_seen":       s["last_seen"],
            "last_message":    s["last_message"],
            "bucket":          bucket,
            "spark":           spark,
            "spark_points":    spark_points,
            "msg_spark":       msg_spark,
            "msg_spark_points": msg_spark_points,
        })

    counts = {b: 0 for b in COPILOT_BUCKETS}
    for r in rows:
        counts[r["bucket"]] += 1

    never_rows = sorted(
        (r for r in rows if r["bucket"] == "never"),
        key=lambda r: (
            (r["brand"].get("agency") or "zzz_direct"),
            (r["brand"].get("parent_company") or ""),
            r["brand"]["brand_name"].lower(),
        ),
    )

    visible = rows if not f_bucket else [r for r in rows if r["bucket"] == f_bucket]
    visible.sort(
        key=lambda r: (-r["week_messages"], -r["week_events"], -r["window_events"], r["brand"]["brand_name"].lower()),
    )

    # Roster-wide totals (used by the top KPI strip on /copilot)
    totals = {
        "messages_week":   sum(r["week_messages"]   for r in rows),
        "messages_window": sum(r["window_messages"] for r in rows),
        "msg_users_week":  sum(1 for r in rows if r["week_messages"] > 0),
        "msg_brands_week": sum(1 for r in rows if r["week_messages"] > 0),
    }

    return render_template(
        "copilot.html",
        rows=visible,
        total_rows=len(rows),
        counts=counts,
        f_bucket=f_bucket,
        buckets=COPILOT_BUCKETS,
        never_rows=never_rows,
        days=days,
        day_window=day_window,
        thresholds={"heavy": heavy_th, "moderate": moderate_th},
        totals=totals,
        msg_event=msg_event,
    )


# -------- Creative Production Tracker -----------------------------------

CREATIVE_RANGES = ("7d", "30d", "90d", "month", "custom")

CREATIVE_SOURCE_LABELS = {
    "PRODUCTION_TABLE": "Prod. Table",
    "COPILOT": "Co-Pilot",
    "CREATIVE_AGENT": "Creative Agent",
    "OTHER": "Other",
}

# Sortable overview columns → key function over the assembled row dict.
CREATIVE_SORT_KEYS = {
    "total":            lambda r: (r["total"],),
    "brand":            lambda r: (r["brand_name"].lower(),),
    "copilot":          lambda r: (r["src_copilot"],),
    "production_table": lambda r: (r["src_production_table"],),
    "creative_agent":   lambda r: (r["src_creative_agent"],),
    "brand_made":       lambda r: (r["ct_brand"],),
    "hawky_made":       lambda r: (r["ct_hawky"],),
    "agent_made":       lambda r: (r["ct_agent"],),
    "last_activity":    lambda r: (r["last_activity"] or "",),
}

_CREATIVE_ZERO = {
    "total": 0, "src_production_table": 0, "src_copilot": 0,
    "src_creative_agent": 0, "src_other": 0, "ct_brand": 0, "ct_hawky": 0,
    "ct_agent": 0, "ct_unattributed": 0, "last_activity": None,
}


def _parse_iso_date(s, fallback):
    if not s:
        return fallback
    try:
        return date.fromisoformat(s)
    except ValueError:
        return fallback


def _parse_creatives_filters(args):
    """
    Parse the shared global filters for both creative screens. Returns a dict
    with resolved dates, the equal-length previous window (for the Δ%), the
    validated source/creator enums + their URL tokens, and a `nav_qs` dict of
    global filters to carry across overview ↔ detail navigation.
    """
    today = ist_today()
    rng = args.get("range", "30d")
    if rng not in CREATIVE_RANGES:
        rng = "30d"

    if rng == "custom":
        date_to = _parse_iso_date(args.get("to"), today)
        date_from = _parse_iso_date(args.get("from"), today - timedelta(days=29))
        if date_from > date_to:
            date_from, date_to = date_to, date_from
    elif rng == "month":
        date_to = today
        date_from = today.replace(day=1)
    else:  # 7d / 30d / 90d
        n = int(rng[:-1])
        date_to = today
        date_from = today - timedelta(days=n - 1)

    # Previous equal-length window (PRD: "% change vs the previous equal-length period").
    length = (date_to - date_from).days + 1
    prev_to = date_from - timedelta(days=1)
    prev_from = prev_to - timedelta(days=length - 1)

    source_token = (args.get("source") or "").strip().lower()
    source = store.SOURCE_FILTER_MAP.get(source_token)
    if not source:
        source_token = ""
    creator_token = (args.get("creator") or "").strip().lower()
    creator = store.CREATOR_FILTER_MAP.get(creator_token)
    if not creator:
        creator_token = ""

    q = (args.get("q") or "").strip()
    sort = args.get("sort", "total")
    if sort not in CREATIVE_SORT_KEYS:
        sort = "total"
    dir_ = "asc" if args.get("dir") == "asc" else "desc"

    # Global filters only (no q/sort/dir) — carried across screen navigation.
    nav_qs = {}
    if rng != "30d":
        nav_qs["range"] = rng
    if rng == "custom":
        nav_qs["from"] = date_from.isoformat()
        nav_qs["to"] = date_to.isoformat()
    if source_token:
        nav_qs["source"] = source_token
    if creator_token:
        nav_qs["creator"] = creator_token

    return {
        "range": rng, "date_from": date_from, "date_to": date_to,
        "prev_from": prev_from, "prev_to": prev_to, "length": length,
        "source": source, "source_token": source_token,
        "creator": creator, "creator_token": creator_token,
        "q": q, "sort": sort, "dir": dir_, "nav_qs": nav_qs,
    }


def _creatives_full_params(f):
    """All current filter params (incl. q/sort/dir), non-default ones only."""
    params = dict(f["nav_qs"])
    if f["q"]:
        params["q"] = f["q"]
    if f["sort"] != "total":
        params["sort"] = f["sort"]
    if f["dir"] != "desc":
        params["dir"] = f["dir"]
    return params


def _creative_pct(x, total):
    return round(100 * x / total) if total else 0


def _build_creative_cards(summary, summary_prev, prev_from, data_start):
    """Shared KPI-card model for both creative screens (global or brand-scoped)."""
    total = summary["total"]
    prev_total = summary_prev["total"]
    prev_reliable = bool(data_start) and prev_from.isoformat() >= data_start
    delta_pct = None
    if prev_reliable and prev_total > 0:
        delta_pct = round((total - prev_total) / prev_total * 100)

    src_counts = {
        "PRODUCTION_TABLE": summary["src_production_table"],
        "COPILOT": summary["src_copilot"],
        "CREATIVE_AGENT": summary["src_creative_agent"],
        "OTHER": summary["src_other"],
    }
    top_key = max(src_counts, key=lambda k: src_counts[k]) if total else None
    top_source = {
        "label": CREATIVE_SOURCE_LABELS.get(top_key) if top_key else "—",
        "count": src_counts.get(top_key, 0) if top_key else 0,
        "pct": _creative_pct(src_counts.get(top_key, 0), total) if top_key else 0,
    }
    non_agent = total - summary["ct_agent"]
    coverage = _creative_pct(summary["ct_brand"] + summary["ct_hawky"], non_agent) if non_agent > 0 else None

    return {
        "total": total,
        "delta_pct": delta_pct,
        "prev_reliable": prev_reliable,
        "brand_made": summary["ct_brand"],
        "brand_pct": _creative_pct(summary["ct_brand"], total),
        "brand_users": summary["brand_users"],
        "hawky_made": summary["ct_hawky"],
        "hawky_pct": _creative_pct(summary["ct_hawky"], total),
        "hawky_users": summary["hawky_users"],
        "agent_made": summary["ct_agent"],
        "agent_pct": _creative_pct(summary["ct_agent"], total),
        "unattributed": summary["ct_unattributed"],
        "unattr_pct": _creative_pct(summary["ct_unattributed"], total),
        "top_source": top_source,
        "coverage": coverage,
    }


def _creatives_invariant_ok(summary):
    total = summary["total"]
    if not total:
        return True
    src_sum = (summary["src_production_table"] + summary["src_copilot"]
               + summary["src_creative_agent"] + summary["src_other"])
    ct_sum = (summary["ct_brand"] + summary["ct_hawky"]
              + summary["ct_agent"] + summary["ct_unattributed"])
    return src_sum == total and ct_sum == total


@app.route("/creatives")
def creatives_page():
    f = _parse_creatives_filters(request.args)

    with store.db(cfg.DB_PATH) as conn:
        summary = store.creatives_summary(conn, f["date_from"], f["date_to"], f["source"], f["creator"])
        summary_prev = store.creatives_summary(conn, f["prev_from"], f["prev_to"], f["source"], f["creator"])
        per_brand = store.creatives_by_brand(conn, f["date_from"], f["date_to"], f["source"], f["creator"])
        cbrands = store.list_creative_brands(conn)
        roster = store.list_brands(conn, active_only=True)
        last_sync = store.latest_creative_sync(conn)
        ds = conn.execute("SELECT MIN(ist_date) AS d FROM creatives").fetchone()
    data_start = ds["d"] if ds else None

    # Union: brands with creatives + zero-creative roster brands (inactivity is signal).
    meta = {b["brand_id"]: b for b in cbrands}
    for b in roster:
        meta.setdefault(b["brand_id"], {
            "brand_id": b["brand_id"], "brand_name": b["brand_name"],
            "is_on_roster": 1, "agency": b.get("agency"),
            "parent_company": b.get("parent_company"),
            "instance_label": b.get("instance_label"),
        })

    rows = []
    for bid, b in meta.items():
        c = per_brand.get(bid, _CREATIVE_ZERO)
        total = c["total"]
        rows.append({
            "brand_id": bid,
            "brand_name": b["brand_name"] or bid,
            "is_on_roster": b.get("is_on_roster", 0),
            "agency": b.get("agency"),
            "parent_company": b.get("parent_company"),
            "instance_label": b.get("instance_label"),
            "total": total,
            "src_production_table": c["src_production_table"],
            "src_copilot": c["src_copilot"],
            "src_creative_agent": c["src_creative_agent"],
            "src_other": c["src_other"],
            "ct_brand": c["ct_brand"],
            "ct_hawky": c["ct_hawky"],
            "ct_agent": c["ct_agent"],
            "ct_unattributed": c["ct_unattributed"],
            "last_activity": c["last_activity"],
            "brand_pct": _creative_pct(c["ct_brand"], total),
            "hawky_pct": _creative_pct(c["ct_hawky"], total),
            "agent_pct": _creative_pct(c["ct_agent"], total),
            "unattr_pct": _creative_pct(c["ct_unattributed"], total),
        })

    # Search filters the visible rows only; KPI cards stay on the full window.
    qn = f["q"].lower()
    visible = [r for r in rows
               if not qn or qn in r["brand_name"].lower() or qn in r["brand_id"].lower()]
    visible.sort(key=lambda r: r["brand_name"].lower())  # stable base order
    visible.sort(key=CREATIVE_SORT_KEYS[f["sort"]], reverse=(f["dir"] != "asc"))

    # --- KPI cards (respect source/creator/date filters) ---
    cards = _build_creative_cards(summary, summary_prev, f["prev_from"], data_start)
    if not _creatives_invariant_ok(summary):
        app.logger.warning("Creatives invariant break in window %s..%s: %s",
                            f["date_from"], f["date_to"], summary)

    show_other = summary["src_other"] > 0 or any(r["src_other"] for r in rows)

    # Clear-filter pill URLs + sortable header URLs.
    base = _creatives_full_params(f)

    def _clear(key):
        p = dict(base)
        p.pop(key, None)
        return url_for("creatives_page", **p)

    def _sort_url(col):
        p = dict(base)
        new_dir = "asc" if (f["sort"] == col and f["dir"] != "asc") else "desc"
        p["sort"] = col
        if new_dir != "desc":
            p["dir"] = new_dir
        else:
            p.pop("dir", None)
        if col == "total":
            p.pop("sort", None)
        return url_for("creatives_page", **p)

    clear_urls = {k: _clear(k) for k in ("source", "creator", "q")}
    sort_urls = {col: _sort_url(col) for col in CREATIVE_SORT_KEYS}

    return render_template(
        "creatives.html",
        f=f, rows=visible, total_brands=len(rows),
        cards=cards, show_other=show_other,
        last_sync=last_sync, data_start=data_start,
        source_labels=CREATIVE_SOURCE_LABELS,
        clear_urls=clear_urls, sort_urls=sort_urls,
    )


@app.route("/creatives/brand/<brand_id>")
def creatives_brand_page(brand_id):
    f = _parse_creatives_filters(request.args)

    with store.db(cfg.DB_PATH) as conn:
        meta = store.creative_brand_meta(conn, brand_id)
        if meta is None:
            abort(404)
        summary = store.creatives_summary(conn, f["date_from"], f["date_to"], f["source"], f["creator"], brand_id=brand_id)
        summary_prev = store.creatives_summary(conn, f["prev_from"], f["prev_to"], f["source"], f["creator"], brand_id=brand_id)
        users = store.creatives_brand_users(conn, brand_id, f["date_from"], f["date_to"], f["source"], f["creator"])
        agents = store.creatives_brand_agents(conn, brand_id, f["date_from"], f["date_to"])
        tables_by_user = store.creatives_user_tables(conn, brand_id, f["date_from"], f["date_to"])
        last_sync = store.latest_creative_sync(conn)
        ds = conn.execute("SELECT MIN(ist_date) AS d FROM creatives").fetchone()
    data_start = ds["d"] if ds else None

    cards = _build_creative_cards(summary, summary_prev, f["prev_from"], data_start)
    if not _creatives_invariant_ok(summary):
        app.logger.warning("Creatives invariant break (brand %s) %s..%s: %s",
                            brand_id, f["date_from"], f["date_to"], summary)

    product_base_url = _get_setting("product_base_url", cfg.DEFAULT_PRODUCT_BASE_URL).rstrip("/")

    # Attach production tables + per-row ratio percentages to each user row.
    for u in users:
        u["tables"] = tables_by_user.get(u["email"], [])
        t = u["total"]
        u["brand_pct"] = _creative_pct(u["ct_brand"], t)
        u["hawky_pct"] = _creative_pct(u["ct_hawky"], t)
        u["unattr_pct"] = _creative_pct(u["ct_unattributed"], t)

    # Search filters the user rows by email (the unattributed row has no email).
    qn = f["q"].lower()
    if qn:
        users = [u for u in users if u["email"] and qn in u["email"].lower()]

    show_other = summary["src_other"] > 0 or any(u["src_other"] for u in users)
    back_url = url_for("creatives_page", **f["nav_qs"])

    base = _creatives_full_params(f)

    def _clear(key):
        p = {k: v for k, v in base.items() if k != key}
        return url_for("creatives_brand_page", brand_id=brand_id, **p)

    clear_urls = {k: _clear(k) for k in ("source", "creator", "q")}

    return render_template(
        "creatives_brand.html",
        f=f, brand=meta, cards=cards,
        users=users, agents=agents, show_other=show_other,
        product_base_url=product_base_url, back_url=back_url,
        last_sync=last_sync, data_start=data_start,
        source_labels=CREATIVE_SOURCE_LABELS, clear_urls=clear_urls,
    )


USER_SORT_KEYS = {
    "email":       (lambda u: (u["email"] or "").lower(), "asc"),
    "events":      (lambda u: u["events"],                "desc"),
    "active_days": (lambda u: u["active_days"],           "desc"),
    "pages":       (lambda u: u["pages_seen"],            "desc"),
    "first_seen":  (lambda u: u["first_seen"] or "",      "asc"),
    "last_seen":   (lambda u: u["last_seen"] or "",       "desc"),
}

PAGES_SORT_KEYS = {
    "events":     (lambda p: p["n"],                       "desc"),
    "users":      (lambda p: p["users"],                   "desc"),
    "recent":     (lambda p: p["last_seen"] or "",         "desc"),
    "url":        (lambda p: (p["current_url"] or "").lower(), "asc"),
}

SECTIONS_SORT_KEYS = {
    "events":    (lambda kv: kv[1]["events"],          "desc"),
    "last_seen": (lambda kv: kv[1]["last_seen"] or "", "desc"),
    "sub_page":  (lambda kv: kv[0].lower(),            "asc"),
}


@app.route("/brand/<brand_id>")
def brand_page(brand_id):
    tab = request.args.get("tab", "overview")
    # Legacy: ?tab=trends URLs silently land on Overview (charts moved there in Slice 7).
    if tab == "trends":
        tab = "overview"
    if tab not in BRAND_TABS:
        tab = "overview"

    # Sort params per tab — all URL-backed for shareability.
    u_sort  = request.args.get("usort",  "events");  u_dir = request.args.get("udir", "")
    p_sort  = request.args.get("psort",  "events");  p_dir = request.args.get("pdir", "")
    s_sort  = request.args.get("ssort",  "events");  s_dir = request.args.get("sdir", "")
    if u_sort not in USER_SORT_KEYS:     u_sort = "events"
    if p_sort not in PAGES_SORT_KEYS:    p_sort = "events"
    if s_sort not in SECTIONS_SORT_KEYS: s_sort = "events"
    # Drill-down filter from "Most recent events" → Users tab
    u_filter_email = (request.args.get("uemail") or "").strip().lower()
    u_filter_did   = (request.args.get("udid") or "").strip()

    day_window = _get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW)
    weekend = _get_weekend_set()
    today = ist_today()
    ist_from = today - timedelta(days=day_window - 1)

    users = sections = pages = recent_events = None
    msg_event = _get_copilot_message_event()

    with store.db(cfg.DB_PATH) as conn:
        rec = conn.execute("SELECT * FROM brands WHERE brand_id=?", (brand_id,)).fetchone()
        if not rec:
            abort(404)
        brand = dict(rec)
        agg = store.events_by_brand_day(conn, ist_from, today)
        module_counts = store.module_counts_by_brand(conn, ist_from, today)
        copilot_msgs = store.brand_copilot_messages(conn, brand_id, ist_from, today, msg_event)
        # Overview now owns the trends charts AND the recent-events preview.
        module_meta = None
        if tab == "overview":
            recent_events = store.brand_recent_events(conn, brand_id, limit=10)
            trend = store.brand_events_by_day_module(conn, brand_id, ist_from, today)
            module_meta = store.brand_module_meta(conn, brand_id, ist_from, today)
            # All metric series for the dropdown — per-brand, per-day.
            brand_metrics = store.brand_metric_series_by_day(
                conn, brand_id, ist_from, today, msg_event,
            ) if hasattr(store, "brand_metric_series_by_day") else None
        else:
            trend = None
            brand_metrics = None
        user_day_module = None
        if tab == "users":
            users = store.brand_user_summary(conn, brand_id, ist_from, today)
            if u_filter_email:
                users = [u for u in users if (u.get("email") or "").lower() == u_filter_email]
            if u_filter_did:
                users = [u for u in users if u.get("distinct_id") == u_filter_did]
            user_day_module = store.brand_user_day_module(conn, brand_id, ist_from, today)
        if tab == "sections":
            sections = store.brand_section_rollup(conn, brand_id, ist_from, today, ALL_MODULES)
        if tab == "pages":
            pages = store.brand_top_pages(conn, brand_id, ist_from, today, sort=p_sort, limit=100)

    days = last_n_dates_ist(day_window, end=today)
    rows = _build_rows([brand], agg, days, weekend, today, module_counts)
    row = rows[0] if rows else None

    # Apply sorts in Python (small result sets — fast).
    if users:
        key_fn, default_dir = USER_SORT_KEYS[u_sort]
        u_dir = u_dir if u_dir in ("asc", "desc") else default_dir
        users.sort(key=key_fn, reverse=(u_dir == "desc"))
        # Decorate each user with a 21-day activity strip matching the brand-row
        # strip on `/`. Tooltips include per-module breakdown so a single hover
        # answers "what module did this user touch on day X."
        if user_day_module is not None:
            for u in users:
                per_day = user_day_module.get(u["distinct_id"], {})
                cells = []
                for d in days:
                    iso = d.isoformat()
                    day = per_day.get(iso, {})
                    total = day.get("total", 0)
                    is_wknd = is_weekend(d, weekend)
                    mods_with_counts = [
                        (m, day.get(m, 0)) for m in ALL_MODULES if day.get(m, 0) > 0
                    ]
                    parts = [d.strftime("%a · %d %b"), f"{total} events"]
                    if mods_with_counts:
                        parts.append(" · ".join(f"{m} {c}" for m, c in mods_with_counts))
                    if is_wknd:
                        parts.append("weekend")
                    if d == today:
                        parts.append("today")
                    cells.append({
                        "date": iso,
                        "events": total,
                        "is_weekend": is_wknd,
                        "is_today": d == today,
                        "tip": " · ".join(parts),
                    })
                u["day_cells"] = cells
    else:
        u_dir = u_dir if u_dir in ("asc", "desc") else USER_SORT_KEYS[u_sort][1]
    if pages:
        key_fn, default_dir = PAGES_SORT_KEYS[p_sort]
        p_dir = p_dir if p_dir in ("asc", "desc") else default_dir
        pages.sort(key=key_fn, reverse=(p_dir == "desc"))
    else:
        p_dir = p_dir if p_dir in ("asc", "desc") else PAGES_SORT_KEYS[p_sort][1]
    if sections:
        key_fn, default_dir = SECTIONS_SORT_KEYS[s_sort]
        s_dir = s_dir if s_dir in ("asc", "desc") else default_dir
        for bucket in sections.values():
            bucket["sub_pages"] = sorted(bucket["sub_pages"], key=key_fn,
                                         reverse=(s_dir == "desc"))
    else:
        s_dir = s_dir if s_dir in ("asc", "desc") else SECTIONS_SORT_KEYS[s_sort][1]

    # Back-link to the list page (preserve filters if the user came from there).
    back_url = url_for("index")
    ref = request.referrer or ""
    if ref.startswith(request.host_url) and "/brand/" not in ref:
        back_url = ref

    tab_urls = {t: url_for("brand_page", brand_id=brand_id, tab=t) for t in BRAND_TABS}

    chart_trend = None
    if tab == "overview" and trend is not None:
        cats = [d.isoformat() for d in days]

        def _series(key):
            return [trend.get(c, {}).get(key, 0) for c in cats]

        # Compose all metric-dropdown options. Per-module + Co-Pilot messages
        # come from `trend` (already brand-scoped). "Users" and "Co-Pilot users"
        # come from brand_metrics if available, else fall back to zeros.
        bm = brand_metrics or {}
        def _bm(k):
            return [bm.get(c, {}).get(k, 0) for c in cats]

        chart_trend = {
            "categories": cats,
            # Backwards-compat keys used by the existing stacked-area chart:
            "events":               _series("total"),
            "Creative Intel":       _series("Creative Intel"),
            "Competitive Intel":    _series("Competitive Intel"),
            "Production+Playbooks": _series("Production+Playbooks"),
            "Co-Pilot":             _series("Co-Pilot"),
            "Agents":               _series("Agents"),
            # New metrics for the dropdown on Overview's events/day chart:
            "metrics": {
                "events":           {"label": "Events",                "data": _series("total")},
                "copilot_messages": {"label": "Co-Pilot messages sent","data": _bm("copilot_messages")},
                "copilot_users":    {"label": "Co-Pilot users",        "data": _bm("copilot_users")},
                "users":            {"label": "Distinct users",        "data": _bm("users")},
                "module_creative":  {"label": "Module: Creative Intel",       "data": _series("Creative Intel")},
                "module_compet":    {"label": "Module: Competitive Intel",    "data": _series("Competitive Intel")},
                "module_prod":      {"label": "Module: Production+Playbooks", "data": _series("Production+Playbooks")},
                "module_copilot":   {"label": "Module: Co-Pilot",             "data": _series("Co-Pilot")},
                "module_agents":    {"label": "Module: Agents",               "data": _series("Agents")},
            },
        }

    # Pre-build sort-link helpers for the templates (cheap closures).
    def _users_link(key):
        new_dir = "asc" if (u_sort == key and u_dir == "desc") else "desc"
        return url_for("brand_page", brand_id=brand_id, tab="users", usort=key, udir=new_dir)

    def _pages_link(key):
        new_dir = "asc" if (p_sort == key and p_dir == "desc") else "desc"
        return url_for("brand_page", brand_id=brand_id, tab="pages", psort=key, pdir=new_dir)

    def _sections_link(key):
        new_dir = "asc" if (s_sort == key and s_dir == "desc") else "desc"
        return url_for("brand_page", brand_id=brand_id, tab="sections", ssort=key, sdir=new_dir)

    return render_template(
        "brand.html",
        brand=brand, row=row,
        days=days, day_window=day_window,
        modules=ALL_MODULES,
        tab=tab, tabs=BRAND_TABS, tab_urls=tab_urls, back_url=back_url,
        users=users, sections=sections, pages=pages,
        u_sort=u_sort, u_dir=u_dir, users_link=_users_link,
        u_filter_email=u_filter_email, u_filter_did=u_filter_did,
        p_sort=p_sort, p_dir=p_dir, pages_link=_pages_link,
        s_sort=s_sort, s_dir=s_dir, sections_link=_sections_link,
        recent_events=recent_events,
        chart_trend=chart_trend,
        module_meta=module_meta,
        copilot_msgs=copilot_msgs, msg_event=msg_event,
    )


# -------- /config routes (Slice 1, with parent_company added) ------------

@app.route("/config")
def config_page():
    with store.db(cfg.DB_PATH) as conn:
        brands = store.list_brands(conn, active_only=False)
        allow, deny = store.get_exclusions(conn)
        rules = store.list_rules(conn)
        settings = {
            "refresh_min": store.get_setting(conn, "refresh_min", cfg.DEFAULT_REFRESH_MIN),
            "day_window": store.get_setting(conn, "day_window", cfg.DEFAULT_DAY_WINDOW),
            "weekend_days": store.get_setting(conn, "weekend_days", cfg.DEFAULT_WEEKEND_DAYS),
            "timezone": store.get_setting(conn, "timezone", cfg.DEFAULT_TIMEZONE),
            "hawky_domains": store.get_setting(conn, "hawky_domains", cfg.DEFAULT_HAWKY_DOMAINS),
            "hawky_substrings": store.get_setting(conn, "hawky_substrings", cfg.DEFAULT_HAWKY_SUBSTRINGS),
            "copilot_heavy": store.get_setting(conn, "copilot_heavy", cfg.DEFAULT_COPILOT_HEAVY),
            "copilot_moderate": store.get_setting(conn, "copilot_moderate", cfg.DEFAULT_COPILOT_MODERATE),
            "copilot_message_event": store.get_setting(conn, "copilot_message_event", cfg.DEFAULT_COPILOT_MESSAGE_EVENT),
            "snapshot_cap": store.get_setting(conn, "snapshot_cap", cfg.DEFAULT_SNAPSHOT_CAP),
            "product_base_url": store.get_setting(conn, "product_base_url", cfg.DEFAULT_PRODUCT_BASE_URL),
        }
        recent = store.recent_runs(conn, n=10)
        creative_syncs = store.recent_creative_syncs(conn, n=10)

    return render_template(
        "config.html",
        brands=brands, allow=sorted(allow), deny=sorted(deny),
        rules=rules, rule_operators=store.HAWKY_RULE_OPERATORS,
        settings=settings, recent=recent,
        creative_syncs=creative_syncs,
        mongo_configured=bool(cfg.MONGO_URI),
        active_tab=request.args.get("tab", "brands"),
    )


@app.route("/config/brand", methods=["POST"])
def config_brand_upsert():
    f = request.form
    bid = (f.get("brand_id") or "").strip()
    if not bid:
        flash("brand_id is required", "error")
        return redirect(url_for("config_page", tab="brands"))
    with store.db(cfg.DB_PATH) as conn:
        store.upsert_brand(
            conn,
            brand_id=bid,
            brand_name=(f.get("brand_name") or "").strip(),
            instance_label=(f.get("instance_label") or "").strip() or None,
            agency=(f.get("agency") or "").strip() or None,
            parent_company=(f.get("parent_company") or "").strip() or None,
            is_active=1 if f.get("is_active") == "on" else 0,
        )
    flash(f"Saved {bid}", "ok")
    return redirect(url_for("config_page", tab="brands"))


@app.route("/config/brand/<brand_id>/delete", methods=["POST"])
def config_brand_delete(brand_id):
    with store.db(cfg.DB_PATH) as conn:
        store.delete_brand(conn, brand_id)
    flash(f"Deleted {brand_id}", "ok")
    return redirect(url_for("config_page", tab="brands"))


@app.route("/config/exclusion", methods=["POST"])
def config_exclusion_upsert():
    f = request.form
    email = (f.get("email") or "").strip().lower()
    kind = f.get("kind") or "deny"
    if not email or kind not in ("allow", "deny"):
        flash("email and kind required", "error")
        return redirect(url_for("config_page", tab="hawky"))
    with store.db(cfg.DB_PATH) as conn:
        store.upsert_exclusion(conn, email, kind, note=f.get("note"))
    return redirect(url_for("config_page", tab="hawky"))


@app.route("/config/exclusion/<path:email>/delete", methods=["POST"])
def config_exclusion_delete(email):
    with store.db(cfg.DB_PATH) as conn:
        store.delete_exclusion(conn, email)
    return redirect(url_for("config_page", tab="hawky"))


@app.route("/config/rule", methods=["POST"])
def config_rule_upsert():
    f = request.form
    operator = (f.get("operator") or "").strip().lower()
    value = (f.get("value") or "").strip()
    kind = (f.get("kind") or "").strip().lower()
    if operator not in store.HAWKY_RULE_OPERATORS or kind not in store.HAWKY_RULE_KINDS or not value:
        flash("Rule needs operator + value + kind", "error")
        return redirect(url_for("config_page", tab="hawky"))
    try:
        with store.db(cfg.DB_PATH) as conn:
            store.upsert_rule(
                conn, operator=operator, value=value, kind=kind,
                note=(f.get("note") or "").strip() or None,
            )
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("config_page", tab="hawky"))
    flash(f"Rule saved: email {operator.replace('_',' ')} \"{value}\" → {kind}", "ok")
    return redirect(url_for("config_page", tab="hawky"))


@app.route("/config/rule/<int:rule_id>/delete", methods=["POST"])
def config_rule_delete(rule_id):
    with store.db(cfg.DB_PATH) as conn:
        store.delete_rule(conn, rule_id)
    flash(f"Rule #{rule_id} deleted", "ok")
    return redirect(url_for("config_page", tab="hawky"))


@app.route("/config/settings", methods=["POST"])
def config_settings_save():
    f = request.form
    keys = (
        "refresh_min", "day_window", "weekend_days", "timezone", "hawky_domains",
        "hawky_substrings", "copilot_heavy", "copilot_moderate",
        "copilot_message_event", "snapshot_cap", "product_base_url",
    )
    with store.db(cfg.DB_PATH) as conn:
        for k in keys:
            if k in f:
                store.set_setting(conn, k, f[k])
    flash("Settings saved", "ok")
    return redirect(url_for("config_page", tab="settings"))


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    do_snapshot = request.form.get("snapshot") == "1" or request.args.get("snapshot") == "1"

    def _do():
        try:
            run_refresh(
                cfg.DB_PATH, mp_client,
                kind="manual",
                day_window=_get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW),
                hawky_domains=_get_hawky_domains(),
                hawky_substrings=_get_hawky_substrings(),
                snapshot=do_snapshot,
                snapshot_cap=_get_int_setting("snapshot_cap", cfg.DEFAULT_SNAPSHOT_CAP),
            )
        except Exception:
            app.logger.exception("Manual refresh failed")

    Thread(target=_do, daemon=True).start()
    return jsonify({"started": True, "snapshot": do_snapshot})


@app.route("/api/reapply-hawky-filter", methods=["POST"])
def api_reapply_hawky_filter():
    """
    Retroactively prune events from any profile whose email now matches the
    Hawky filter. Useful after editing hawky_domains / hawky_substrings /
    allow / deny — saves a full Mixpanel re-fetch.
    """
    deleted, dropped_ids, sample = cleanup_hawky_events(
        cfg.DB_PATH, _get_hawky_domains(), _get_hawky_substrings(),
    )
    if request.headers.get("Accept", "").startswith("application/json") \
            or request.args.get("json") == "1":
        return jsonify({
            "events_deleted": deleted,
            "distinct_ids_dropped": dropped_ids,
            "sample_emails": sample,
        })
    flash(
        f"Removed {deleted:,} events from {dropped_ids} Hawky-internal user(s). "
        f"Sample: {', '.join(sample[:5])}{'…' if len(sample) > 5 else ''}",
        "ok",
    )
    return redirect(url_for("config_page", tab="hawky"))


@app.route("/api/refresh-status")
def api_refresh_status():
    with store.db(cfg.DB_PATH) as conn:
        last = store.latest_run(conn)
    return jsonify(last or {})


# -------- creatives sync (Mongo) ----------------------------------------

def _creatives_sync_job(kind="auto"):
    """Run the Mongo→SQLite creatives sync. No-op when MONGO_URI is unset."""
    if not cfg.MONGO_URI:
        return
    run_creatives_sync(cfg.DB_PATH, cfg.MONGO_URI, cfg.MONGO_DB, kind=kind)


@app.route("/api/creatives-sync", methods=["POST"])
def api_creatives_sync():
    if not cfg.MONGO_URI:
        return jsonify({"started": False, "error": "MONGO_URI not configured"}), 400

    def _do():
        try:
            _creatives_sync_job(kind="manual")
        except Exception:
            app.logger.exception("Manual creatives sync failed")

    Thread(target=_do, daemon=True).start()
    return jsonify({"started": True})


@app.route("/api/creatives-sync-status")
def api_creatives_sync_status():
    with store.db(cfg.DB_PATH) as conn:
        last = store.latest_creative_sync(conn)
    return jsonify(last or {})


@app.route("/api/snapshot", methods=["POST"])
def api_snapshot():
    """
    Fast-path: capture the current events-table state as a snapshot. Does NOT
    re-fetch from Mixpanel — that's what Refresh is for. Returns the new
    snapshot id immediately.
    """
    label = (request.form.get("label") or request.args.get("label") or "").strip() or None
    day_window = _get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW)
    cap = _get_int_setting("snapshot_cap", cfg.DEFAULT_SNAPSHOT_CAP)
    today = ist_today()
    ist_from = today - timedelta(days=day_window - 1)
    with store.db(cfg.DB_PATH) as conn:
        snap_id = store.write_current_snapshot(
            conn, ist_from, today,
            label=label or f"manual @ {ist_now().isoformat(timespec='seconds')}",
            cap=cap,
        )
    return jsonify({"snapshot_id": snap_id, "label": label}), 201


@app.route("/compare")
def compare_page():
    """
    Two modes:
      ?mode=windows&a_from=&a_to=&b_from=&b_to=
      ?mode=snapshots&snap_a=&snap_b=

    Both render the same dumbbell + delta table. URL-shareable.
    """
    mode = (request.args.get("mode") or "windows").lower()
    if mode not in ("windows", "snapshots"):
        mode = "windows"

    today = ist_today()
    # Default windows: this 7d vs prior 7d
    default_a_to = today
    default_a_from = today - timedelta(days=6)
    default_b_to = default_a_from - timedelta(days=1)
    default_b_from = default_b_to - timedelta(days=6)

    def _parse_date(s, fallback):
        if not s:
            return fallback
        try:
            return date.fromisoformat(s)
        except ValueError:
            return fallback

    a_from = _parse_date(request.args.get("a_from"), default_a_from)
    a_to   = _parse_date(request.args.get("a_to"),   default_a_to)
    b_from = _parse_date(request.args.get("b_from"), default_b_from)
    b_to   = _parse_date(request.args.get("b_to"),   default_b_to)

    snap_a_id = request.args.get("snap_a")
    snap_b_id = request.args.get("snap_b")

    delta_rows = []
    summary = {"before_total": 0, "after_total": 0, "delta_total": 0}
    a_label = b_label = None
    snapshots = []

    with store.db(cfg.DB_PATH) as conn:
        brands = store.list_brands(conn, active_only=False)
        snapshots = store.list_snapshots(conn, limit=30, include_payload=True)
        brand_meta = {b["brand_id"]: b for b in brands}

        if mode == "windows":
            # 'after' = period A (the more recent / focus window)
            # 'before' = period B (the comparison baseline)
            after_totals  = store._brand_totals_for_window(conn, a_from, a_to)
            before_totals = store._brand_totals_for_window(conn, b_from, b_to)
            a_label = f"A · {a_from} → {a_to}"
            b_label = f"B · {b_from} → {b_to}"
            delta_rows = store.compare_brand_totals(before_totals, after_totals, brand_meta)
        else:
            snap_a = store.get_snapshot(conn, int(snap_a_id)) if snap_a_id and snap_a_id.isdigit() else None
            snap_b = store.get_snapshot(conn, int(snap_b_id)) if snap_b_id and snap_b_id.isdigit() else None
            if snap_a and snap_b:
                after_totals  = store._brand_totals_from_payload(snap_a["payload"])
                before_totals = store._brand_totals_from_payload(snap_b["payload"])
                a_label = f"A · {snap_a['label'] or 'snap'} @ {snap_a['created_at']}"
                b_label = f"B · {snap_b['label'] or 'snap'} @ {snap_b['created_at']}"
                delta_rows = store.compare_brand_totals(before_totals, after_totals, brand_meta)

    summary["before_total"] = sum(r["before"] for r in delta_rows)
    summary["after_total"]  = sum(r["after"]  for r in delta_rows)
    summary["delta_total"]  = summary["after_total"] - summary["before_total"]

    # Δ-table column sort — URL-backed.
    delta_sort_keys = {
        "delta_abs": (lambda r: (-abs(r["delta"]), -r["after"], r["brand_name"].lower()), "desc"),
        "delta":     (lambda r: r["delta"],         "desc"),
        "pct":       (lambda r: r["pct"],           "desc"),
        "after":     (lambda r: r["after"],         "desc"),
        "before":    (lambda r: r["before"],        "desc"),
        "name":      (lambda r: r["brand_name"].lower(), "asc"),
    }
    d_sort = request.args.get("dsort", "delta_abs")
    d_dir  = request.args.get("ddir", "")
    if d_sort not in delta_sort_keys:
        d_sort = "delta_abs"
    key_fn, default_dir = delta_sort_keys[d_sort]
    d_dir = d_dir if d_dir in ("asc", "desc") else default_dir
    if d_sort == "delta_abs":
        # delta_abs key already encodes desc-sort tie-breakers; use it as-is.
        delta_rows.sort(key=key_fn)
        if d_dir == "asc":
            delta_rows.reverse()
    else:
        delta_rows.sort(key=key_fn, reverse=(d_dir == "desc"))

    def _delta_link(key):
        new_dir = "asc" if (d_sort == key and d_dir == "desc") else "desc"
        params = dict(request.args)
        params["dsort"] = key
        params["ddir"] = new_dir
        return url_for("compare_page", **params)

    # Charts: top N by absolute Δ for the dumbbell (don't render 38 bars).
    top = sorted(
        [r for r in delta_rows if r["before"] > 0 or r["after"] > 0],
        key=lambda r: (-abs(r["delta"]), -r["after"], r["brand_name"].lower()),
    )[:20]
    chart = {
        "categories": [r["brand_name"] for r in top],
        "series": [
            {"name": "Before (B)", "data": [r["before"] for r in top]},
            {"name": "After (A)",  "data": [r["after"]  for r in top]},
        ],
    }

    # Enrich snapshot dropdown labels with event/brand counts so two snapshots
    # don't look identical at a glance.
    for s in snapshots:
        try:
            payload = json.loads(s.get("payload") or "{}")
            by_brand_day = payload.get("by_brand_day") or {}
            n_brands = len(by_brand_day)
            n_events = sum(
                v.get("events", 0)
                for days_map in by_brand_day.values()
                for v in days_map.values()
            )
            s["meta"] = f"{n_events:,} events · {n_brands} brands"
        except Exception:
            s["meta"] = "—"

    return render_template(
        "compare.html",
        mode=mode,
        a_from=a_from, a_to=a_to, b_from=b_from, b_to=b_to,
        snap_a_id=int(snap_a_id) if snap_a_id and snap_a_id.isdigit() else None,
        snap_b_id=int(snap_b_id) if snap_b_id and snap_b_id.isdigit() else None,
        a_label=a_label, b_label=b_label,
        delta_rows=delta_rows, summary=summary, chart=chart,
        snapshots=snapshots,
        d_sort=d_sort, d_dir=d_dir, delta_link=_delta_link,
    )


# -------- bootstrap ------------------------------------------------------

def _bootstrap():
    store.init_db(cfg.DB_PATH).close()
    _seed_settings_if_empty()
    _seed_brands_if_empty()


_bootstrap()
_daemon = RefreshDaemon(
    cfg.DB_PATH,
    mp_client,
    get_interval_min=lambda: _get_int_setting("refresh_min", cfg.DEFAULT_REFRESH_MIN),
    get_day_window=lambda: _get_int_setting("day_window", cfg.DEFAULT_DAY_WINDOW),
    get_hawky_domains=_get_hawky_domains,
    get_hawky_substrings=_get_hawky_substrings,
    # Mongo creatives sync rides the same cadence, isolated from the Mixpanel
    # refresh (a Mongo outage can't break the core pipeline, and vice versa).
    extra_jobs=[_creatives_sync_job],
)
_daemon.start(initial_delay=cfg.DEFAULT_INITIAL_REFRESH_DELAY)


if __name__ == "__main__":
    # Local dev only. In production we run via `gunicorn -w 1 app:app`.
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", 5050)),
            debug=False)
