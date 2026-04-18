"""
FilterConfig → DuckDB SQL WHERE clause translator.

Converts the Python filter config dict (used by ``compile_filter`` in normal
mode) into a parameterized SQL WHERE clause for DuckDB.  Every user value uses
``?`` placeholders — **never** f-string interpolation.

DuckDB dialect differences from SQLite:
  • json_extract_string(col, '$.key')   vs  json_extract(col, '$.key')
  • TRY_CAST(x AS DOUBLE)               vs  CAST(x AS REAL)
  • regexp_matches(col, pat)            vs  REGEXP(pat, col) UDF
  • CONTAINS(col, term)                 vs  INSTR(col, term) > 0
  • Timestamps stored as TEXT (ISO-8601) — text comparison still works identically

Architecture 1 (Arrow table) note
──────────────────────────────────
The DuckDB connection in _FilterThread operates on an in-memory Arrow table that
contains only metadata columns.  Two columns present in the old SQLite schema are
NOT available:

  • search_text      — was a SQLite STORED GENERATED COLUMN; replaced here by
                       SEARCH_TEXT_EXPR, a DuckDB expression that produces the
                       same concatenated lower-case blob at query time.
  • event_data_json  — kept on disk in Parquet; lazy-loaded only for the
                       selected row.  ``conditions`` clauses that reference it
                       are stripped in ArrowTableModel.apply_filter() before
                       this function is called.
"""

from __future__ import annotations

import logging
import re as _re
from typing import Any

logger = logging.getLogger(__name__)

# ── Search-text expression ─────────────────────────────────────────────────────
# Replaces the old SQLite STORED GENERATED COLUMN `search_text`.
# Produces a single lower-cased blob from all indexed metadata columns.
# Used by _term_clause() for both plain-text and regex text searches.
# Also imported by heavyweight_model._ARROW_SEARCH_EXPR so there is one
# canonical definition.
SEARCH_TEXT_EXPR: str = (
    "lower("
    "CAST(event_id AS VARCHAR) || ' ' || "
    "COALESCE(level_name,      '') || ' ' || "
    "COALESCE(channel,         '') || ' ' || "
    "COALESCE(provider,        '') || ' ' || "
    "COALESCE(computer,        '') || ' ' || "
    "COALESCE(user_id,         '') || ' ' || "
    "COALESCE(source_file,     '') || ' ' || "
    "COALESCE(ed_subject_user, '') || ' ' || "
    "COALESCE(ed_target_user,  '') || ' ' || "
    "COALESCE(ed_ip_address,   '') || ' ' || "
    "COALESCE(ed_new_process,  '')"
    ")"
)

# ── Full-text expression for Phase 2 Parquet search ────────────────────────────
# Like SEARCH_TEXT_EXPR but also includes event_data_json so that paths, process
# names, and other event-data values are searchable in Juggernaut mode.
# Used exclusively in text_config_to_parquet_sql() — NOT in filter_config_to_sql()
# (which runs against the Arrow table that does not contain event_data_json).
SEARCH_TEXT_EXPR_FULL: str = (
    "lower("
    "CAST(event_id AS VARCHAR) || ' ' || "
    "COALESCE(level_name,      '') || ' ' || "
    "COALESCE(channel,         '') || ' ' || "
    "COALESCE(provider,        '') || ' ' || "
    "COALESCE(computer,        '') || ' ' || "
    "COALESCE(user_id,         '') || ' ' || "
    "COALESCE(source_file,     '') || ' ' || "
    "COALESCE(ed_subject_user, '') || ' ' || "
    "COALESCE(ed_target_user,  '') || ' ' || "
    "COALESCE(ed_ip_address,   '') || ' ' || "
    "COALESCE(ed_new_process,  '') || ' ' || "
    "COALESCE(event_data_json, '')"
    ")"
)

# Only alphanumeric, underscore, dot, and hyphen are allowed in a json_extract
# path key ($.key).  Single quotes, braces, or spaces would break the SQL
# literal and potentially cause a syntax error crash.
_SAFE_JSON_KEY_RE = _re.compile(r"^[\w.\-]+$")

# Top-level Arrow/Parquet columns that exist as real SQL columns in the
# DuckDB table — NOT inside event_data_json.  Conditions on these names
# must reference the column directly instead of going through
# json_extract_string(event_data_json, '$.name'), which would always
# return NULL for them.
_TOP_LEVEL_COLS: frozenset[str] = frozenset({
    "event_id", "level", "level_name", "channel", "provider",
    "computer", "user_id", "timestamp_utc", "source_file",
    "record_id", "task",
    "ed_subject_user", "ed_target_user", "ed_ip_address", "ed_new_process",
})

# Windows Event Log level name → integer ID
_LEVEL_NAME_TO_ID: dict[str, int] = {
    "LogAlways":   0,
    "Critical":    1,
    "Error":       2,
    "Warning":     3,
    "Information": 4,
    "Verbose":     5,
}


def _escape_like(s: str) -> str:
    """Escape LIKE/ILIKE special characters in a user-supplied value.

    DuckDB LIKE treats ``%`` (any sequence), ``_`` (any single char), and the
    configured ESCAPE char as special.  User input must be sanitised so that
    e.g. ``SERVER%01`` matches literally instead of acting as a wildcard.
    """
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _level_to_int(x) -> "int | None":
    """Convert a level name or numeric value to int. Returns None for unrecognised values."""
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        if x in _LEVEL_NAME_TO_ID:
            return _LEVEL_NAME_TO_ID[x]
        try:
            return int(x)
        except ValueError:
            return None  # e.g. "Audit Success", "Audit Failure" — not a level int
    return None


def filter_config_to_sql(fc: dict) -> tuple[str, list[Any]]:
    """
    Convert a FilterConfig dict to ``(where_clause, params)``.

    Returns ``("1=1", [])`` when no filters are active.
    """
    if not fc:
        return "1=1", []

    clauses: list[str] = []
    params: list[Any] = []

    cs = fc.get("case_sensitive", False)

    def _like_op() -> str:
        """Return LIKE (case-sensitive) or ILIKE (case-insensitive).

        Using DuckDB's native ILIKE instead of lower(col) LIKE lower(val) avoids
        the per-row lower() call and lets DuckDB use vectorised collation paths.
        Zone maps and bloom filters still apply on the raw column value.
        """
        return "LIKE" if cs else "ILIKE"

    # Keep _lw / _lv for CONTAINS() and json_extract paths that still need lowercasing.
    def _lw(col: str) -> str:
        return col if cs else f"lower({col})"

    def _lv(val: str) -> str:
        return val if cs else val.lower()

    # ── event_ids ─────────────────────────────────────────────────────────
    if fc.get("event_ids"):
        ph = ", ".join("?" * len(fc["event_ids"]))
        clauses.append(f"event_id IN ({ph})")
        params.extend(int(x) for x in fc["event_ids"])

    if fc.get("exclude_event_ids"):
        ph = ", ".join("?" * len(fc["exclude_event_ids"]))
        clauses.append(f"event_id NOT IN ({ph})")
        params.extend(int(x) for x in fc["exclude_event_ids"])

    # ── event_id_expr (ELE-style) ─────────────────────────────────────────
    expr = fc.get("event_id_expr", "")
    if expr:
        try:
            from evtx_tool.core.filters import parse_event_id_expression
            inc_ids, exc_ids = parse_event_id_expression(expr)
            is_exclude_mode = fc.get("event_id_exclude", False)

            if inc_ids:
                ph = ", ".join("?" * len(inc_ids))
                if is_exclude_mode:
                    clauses.append(f"event_id NOT IN ({ph})")
                else:
                    clauses.append(f"event_id IN ({ph})")
                params.extend(sorted(inc_ids))
            if exc_ids:
                ph = ", ".join("?" * len(exc_ids))
                clauses.append(f"event_id NOT IN ({ph})")
                params.extend(sorted(exc_ids))
        except Exception as exc:
            logger.warning("filter_sql: failed to parse event_id_expr %r: %s", expr, exc)

    # ── levels ────────────────────────────────────────────────────────────
    if fc.get("levels"):
        level_ints = [v for x in fc["levels"] if (v := _level_to_int(x)) is not None]
        # Collect level names that have no integer mapping (e.g. "Audit Success",
        # "Audit Failure" — Windows keyword-based levels, not ETW integer levels).
        level_names_only = [
            x for x in fc["levels"]
            if isinstance(x, str) and _level_to_int(x) is None
        ]
        # Skip the clause when ALL standard + keyword levels are present — that
        # is equivalent to "no level filter".  The dialog has 8 checkboxes
        # (6 standard + Audit Success + Audit Failure) and returns [] when all
        # are checked; but if a profile passes all 8, skip the filter.
        _ALL_STANDARD = frozenset([0, 1, 2, 3, 4, 5])
        all_ints_present = (set(level_ints) == _ALL_STANDARD)
        all_names_present = (
            set(level_names_only) >= {"Audit Success", "Audit Failure"}
        )
        # Only skip if BOTH integer levels and keyword levels cover everything
        if not (all_ints_present and (all_names_present or not level_names_only)):
            sub_parts: list[str] = []
            sub_params: list[Any] = []
            if level_ints and set(level_ints) != _ALL_STANDARD:
                ph = ", ".join("?" * len(level_ints))
                sub_parts.append(f"level IN ({ph})")
                sub_params.extend(level_ints)
            if level_names_only:
                ph = ", ".join("?" * len(level_names_only))
                sub_parts.append(f"level_name IN ({ph})")
                sub_params.extend(level_names_only)
            if sub_parts:
                clauses.append(f"({' OR '.join(sub_parts)})")
                params.extend(sub_params)

    # ── date_from / date_to ───────────────────────────────────────────────
    # timestamp_utc is stored as text 'YYYY-MM-DD HH:MM:SS'; SUBSTRING works.
    # Mode is determined by the same checkbox flags used by the normal-mode filter:
    #   date_only  → compare SUBSTRING(timestamp_utc, 1, 10)  (YYYY-MM-DD)
    #   time_only  → compare SUBSTRING(timestamp_utc, 12, 8)  (HH:MM:SS)
    #   separate   → both date portion AND time portion independently
    #   range      → full timestamp_utc text comparison (existing behaviour)
    date_exclude = fc.get("date_exclude", False)
    _date_en     = bool(fc.get("date_enabled"))
    _time_en     = bool(fc.get("time_enabled"))
    _sep_en      = bool(fc.get("separately_enabled"))
    _spec_en     = bool(fc.get("specific_day_enabled"))
    date_from_raw = fc.get("date_from") or ""
    date_to_raw   = fc.get("date_to")   or ""

    if date_from_raw or date_to_raw:
        # Normalise to 'YYYY-MM-DD HH:MM:SS' (strip Z / T separator)
        def _norm(s: str) -> str:
            return s.replace("Z", "").replace("T", " ")[:19]

        df = _norm(date_from_raw) if date_from_raw else ""
        dt = _norm(date_to_raw)   if date_to_raw   else ""

        # Determine mode from checkbox flags
        if _spec_en or (_date_en and _time_en and not _sep_en):
            _dt_mode = "range"
        elif _date_en and _time_en and _sep_en:
            _dt_mode = "separate"
        elif _date_en and not _time_en:
            _dt_mode = "date_only"
        elif _time_en and not _date_en:
            _dt_mode = "time_only"
        else:
            _dt_mode = "range"  # fallback

        # ── Timezone correction ──────────────────────────────────────────
        # The filter dialog emits date_from/date_to in the user's display
        # timezone (e.g. "2025-09-26 00:00:00" means midnight IST when the
        # user views timestamps in IST).  timestamp_utc is stored in UTC.
        # Convert the user's boundary values from the display TZ to UTC so
        # the SQL comparison matches what the user sees in the table.
        try:
            from evtx_tool.gui.models import _tz_state
            from datetime import datetime as _dt_cls, timezone as _tz, timedelta as _td

            _mode = _tz_state.get("mode", "utc")
            _disp_tz = None  # None = UTC, no conversion needed
            if _mode == "local":
                _local_off = _dt_cls.now().astimezone().utcoffset()
                if _local_off:
                    _disp_tz = _tz(offset=_local_off)
            elif _mode == "specific":
                try:
                    from zoneinfo import ZoneInfo
                    _disp_tz = ZoneInfo(_tz_state.get("specific", "UTC"))
                except Exception:
                    pass
            elif _mode == "custom":
                _disp_tz = _tz(offset=_td(minutes=_tz_state.get("custom_offset_min", 0)))

            if _disp_tz is not None:
                def _to_utc(s: str) -> str:
                    """Re-interpret a 'YYYY-MM-DD HH:MM:SS' string from display TZ as UTC."""
                    if not s or len(s) < 19:
                        return s
                    try:
                        naive = _dt_cls.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
                        aware = naive.replace(tzinfo=_disp_tz)
                        utc_dt = aware.astimezone(_tz.utc)
                        return utc_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        return s
                df = _to_utc(df) if df else ""
                dt = _to_utc(dt) if dt else ""
                # Force to "range" mode.  date_only / time_only / separate use
                # SUBSTRING(timestamp_utc, ...) to compare just the date or
                # time portion, but after TZ conversion those portions are in
                # UTC — not the user's display timezone.  The full timestamp
                # comparison is always correct after conversion.
                if _dt_mode in ("date_only", "time_only", "separate"):
                    _dt_mode = "range"
        except Exception as _exc:
            logger.debug("filter_sql: timezone correction skipped: %s", _exc)

        date_parts: list[str] = []

        if _dt_mode == "date_only":
            if df and len(df) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) >= ?")
                params.append(df[:10])
            if dt and len(dt) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) <= ?")
                params.append(dt[:10])

        elif _dt_mode == "time_only":
            _tf = df[11:19] if len(df) >= 19 else ("00:00:00" if df else "")
            _tt = dt[11:19] if len(dt) >= 19 else ("23:59:59" if dt else "")
            if _tf:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) >= ?")
                params.append(_tf)
            if _tt:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) <= ?")
                params.append(_tt)

        elif _dt_mode == "separate":
            # Date range AND time-of-day range applied independently
            if df and len(df) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) >= ?")
                params.append(df[:10])
            if dt and len(dt) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) <= ?")
                params.append(dt[:10])
            _tf = df[11:19] if len(df) >= 19 else ""
            _tt = dt[11:19] if len(dt) >= 19 else ""
            if _tf:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) >= ?")
                params.append(_tf)
            if _tt:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) <= ?")
                params.append(_tt)

        else:  # "range" — full timestamp comparison
            if df and len(df) >= 10:
                date_parts.append("timestamp_utc >= ?")
                params.append(df)
            elif date_from_raw:
                logger.warning("filter_sql: ignoring malformed date_from %r", date_from_raw)
            if dt and len(dt) >= 10:
                date_parts.append("timestamp_utc <= ?")
                params.append(dt)
            elif date_to_raw:
                logger.warning("filter_sql: ignoring malformed date_to %r", date_to_raw)

        if date_parts:
            combined = " AND ".join(date_parts)
            clauses.append(f"NOT ({combined})" if date_exclude else f"({combined})")

    # ── relative_days / relative_hours ────────────────────────────────────
    try:
        rel_days = int(fc.get("relative_days", 0) or 0)
    except (TypeError, ValueError):
        logger.warning("filter_sql: ignoring non-numeric relative_days %r", fc.get("relative_days"))
        rel_days = 0
    try:
        rel_hours = int(fc.get("relative_hours", 0) or 0)
    except (TypeError, ValueError):
        logger.warning("filter_sql: ignoring non-numeric relative_hours %r", fc.get("relative_hours"))
        rel_hours = 0
    if rel_days > 0 or rel_hours > 0:
        total_hours = rel_days * 24 + rel_hours
        rel_exclude = fc.get("relative_exclude", False)
        # DuckDB: use CURRENT_TIMESTAMP - INTERVAL
        cutoff_expr = f"(CURRENT_TIMESTAMP - INTERVAL '{total_hours} hours')::VARCHAR"
        if rel_exclude:
            clauses.append(f"timestamp_utc < {cutoff_expr}")
        else:
            clauses.append(f"timestamp_utc >= {cutoff_expr}")

    # ── computers ─────────────────────────────────────────────────────────
    if fc.get("computers"):
        comp_exclude = fc.get("computer_exclude", False)
        op = _like_op()
        sub = " OR ".join(f"computer {op} ? ESCAPE '\\'" for _ in fc["computers"])
        params.extend(f"%{_escape_like(c)}%" for c in fc["computers"])
        clause = f"({sub})"
        clauses.append(f"NOT {clause}" if comp_exclude else clause)

    # ── sources ───────────────────────────────────────────────────────────
    if fc.get("sources"):
        src_exclude = fc.get("source_exclude", False)
        op = _like_op()
        sub_parts = []
        for s in fc["sources"]:
            sub_parts.append(f"provider {op} ? ESCAPE '\\'")
            sub_parts.append(f"channel {op} ? ESCAPE '\\'")
            _es = _escape_like(s)
            params.extend([f"%{_es}%", f"%{_es}%"])
        clause = f"({' OR '.join(sub_parts)})"
        clauses.append(f"NOT {clause}" if src_exclude else clause)

    # ── categories (channel names) ────────────────────────────────────────
    if fc.get("categories"):
        cat_exclude = fc.get("category_exclude", False)
        op = _like_op()
        sub = " OR ".join(f"channel {op} ? ESCAPE '\\'" for _ in fc["categories"])
        params.extend(f"%{_escape_like(c)}%" for c in fc["categories"])
        clause = f"({sub})"
        clauses.append(f"NOT {clause}" if cat_exclude else clause)

    # ── users ──────────────────────────────────────────────────────────────
    # Checks user_id (System/Security header SID), ed_subject_user
    # (SubjectUserName), and ed_target_user (TargetUserName) — all pre-extracted
    # Arrow table columns.
    # TODO: SubjectUserSid / TargetUserSid live only in event_data_json (Parquet)
    # and therefore cannot be checked here without adding ed_subject_sid /
    # ed_target_sid as pre-extracted columns to the Arrow schema (engine.py).
    if fc.get("users"):
        usr_exclude = fc.get("user_exclude", False)
        op = _like_op()
        sub_parts = []
        for u in fc["users"]:
            _eu = _escape_like(u)
            for col in ("ed_subject_user", "ed_target_user", "user_id"):
                sub_parts.append(f"{col} {op} ? ESCAPE '\\'")
                params.append(f"%{_eu}%")
        clause = f"({' OR '.join(sub_parts)})"
        clauses.append(f"NOT {clause}" if usr_exclude else clause)

    # ── task_categories ───────────────────────────────────────────────────
    if fc.get("task_categories"):
        task_ints = []
        for x in fc["task_categories"]:
            try:
                task_ints.append(int(x))
            except (ValueError, TypeError):
                logger.warning("filter_sql: skipping non-numeric task_category %r", x)
        if task_ints:
            ph = ", ".join("?" * len(task_ints))
            clauses.append(f"task IN ({ph})")
            params.extend(task_ints)

    # ── text_search ───────────────────────────────────────────────────────
    text_terms = fc.get("text_search")
    if text_terms:
        if isinstance(text_terms, str):
            text_terms = [text_terms]

        mode = fc.get("search_mode", "AND").upper()
        text_regex = fc.get("text_regex", False)
        text_exclude = fc.get("text_exclude", False)

        def _term_clause(term: str) -> str:
            if text_regex:
                # DuckDB native: regexp_matches(expr, pattern [, flags])
                # 'i' flag = case-insensitive; omit for case-sensitive.
                # SEARCH_TEXT_EXPR already lower()s the blob, so case-
                # insensitive matching works on both sides of the regex.
                if cs:
                    params.append(term)
                    return f"regexp_matches({SEARCH_TEXT_EXPR}, ?)"
                else:
                    params.append(term.lower())
                    return f"regexp_matches({SEARCH_TEXT_EXPR}, ?, 'i')"
            else:
                # CONTAINS() on the pre-lowercased expression.
                # term is lowercased by _lv() for case-insensitive match.
                params.append(_lv(term))
                return f"CONTAINS({SEARCH_TEXT_EXPR}, ?)"

        term_clauses = [_term_clause(t) for t in text_terms]
        if mode == "AND":
            combined = f"({' AND '.join(term_clauses)})"
        elif mode == "OR":
            combined = f"({' OR '.join(term_clauses)})"
        elif mode == "NOT":
            combined = f"NOT ({' OR '.join(term_clauses)})"
        else:
            combined = f"({' AND '.join(term_clauses)})"

        if text_exclude and mode != "NOT":
            combined = f"NOT {combined}"
        clauses.append(combined)

    # ── conditions (custom field operators) ────────────────────────────────
    for cond in fc.get("conditions", []):
        name = cond.get("name", "")
        if not name:
            continue

        # Decide whether to reference the column directly (top-level) or via
        # json_extract_string() (event_data sub-field).
        if name in _TOP_LEVEL_COLS:
            # Direct column reference — safe (name comes from a known allowlist).
            # CAST to VARCHAR so all string operators work uniformly even on
            # integer columns like event_id.
            base_expr = f"CAST({name} AS VARCHAR)"
        elif _SAFE_JSON_KEY_RE.match(name):
            # Simple identifier — use dot notation: $.FieldName
            base_expr = f"json_extract_string(event_data_json, '$.{name}')"
        elif '"' not in name and "\\" not in name and "\x00" not in name:
            # Field name contains spaces or other special characters but is
            # otherwise safe — use JSONPath double-quote bracket notation:
            # json_extract_string(col, '$."My Field Name"')
            base_expr = f'json_extract_string(event_data_json, \'$."{name}"\')'
        else:
            logger.warning("filter_sql: skipping condition with unsafe field name %r", name)
            continue

        op = cond.get("operator", "contains")
        val = cond.get("value", "")
        field_expr = base_expr
        if not cs:
            field_expr = f"lower({field_expr})"
            val = val.lower()

        if op == "contains":
            clauses.append(f"CONTAINS(COALESCE({field_expr}, ''), ?)")
            params.append(val)
        elif op == "equals":
            clauses.append(f"COALESCE({field_expr}, '') = ?")
            params.append(val)
        elif op == "starts with":
            clauses.append(f"COALESCE({field_expr}, '') LIKE ? ESCAPE '\\'")
            params.append(f"{_escape_like(val)}%")
        elif op == "ends with":
            clauses.append(f"COALESCE({field_expr}, '') LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(val)}")
        elif op == "not contains":
            clauses.append(f"NOT CONTAINS(COALESCE({field_expr}, ''), ?)")
            params.append(val)
        elif op == "not equals":
            clauses.append(f"COALESCE({field_expr}, '') != ?")
            params.append(val)
        elif op == "regex":
            # DuckDB native regex — case flag applied based on cs setting.
            # Use base_expr (without lower()) so the regex sees the original case
            # when cs=True; the 'i' flag handles case-insensitive matching.
            raw_val = cond.get("value", "")
            raw_field = f"COALESCE({base_expr}, '')"
            if cs:
                clauses.append(f"regexp_matches({raw_field}, ?)")
            else:
                clauses.append(f"regexp_matches({raw_field}, ?, 'i')")
            params.append(raw_val)
        elif op == "greater than":
            # DuckDB TRY_CAST — safe equivalent of SQLite's CAST (won't crash on non-numeric)
            clauses.append(
                f"TRY_CAST({field_expr} AS DOUBLE) > TRY_CAST(? AS DOUBLE)"
            )
            params.append(val)
        elif op == "less than":
            clauses.append(
                f"TRY_CAST({field_expr} AS DOUBLE) < TRY_CAST(? AS DOUBLE)"
            )
            params.append(val)

    if not clauses:
        return "1=1", []
    return " AND ".join(clauses), params


def text_config_to_parquet_sql(fc: dict) -> "tuple[str, list[Any]]":
    """
    Build a CONTAINS / regexp_matches clause for Phase 2 Parquet-based text search.

    Uses SEARCH_TEXT_EXPR_FULL (which includes event_data_json) so that event-data
    values — file paths, process names, package names, etc. — are matched even
    though they are not present in the in-memory Arrow table.

    Called by _FilterThread._apply_with_full_text_search(); never called by
    filter_config_to_sql() (Arrow table path).
    """
    text_terms = fc.get("text_search")
    if not text_terms:
        return "1=1", []
    if isinstance(text_terms, str):
        text_terms = [text_terms]

    cs         = fc.get("case_sensitive", False)
    text_regex = fc.get("text_regex", False)
    text_excl  = fc.get("text_exclude", False)
    mode       = fc.get("search_mode", "AND").upper()
    params: list[Any] = []

    def _lv(val: str) -> str:
        return val if cs else val.lower()

    def _term_clause(term: str) -> str:
        if text_regex:
            # DuckDB native: regexp_matches(expr, pattern [, 'i' flag])
            if cs:
                params.append(term)
                return f"regexp_matches({SEARCH_TEXT_EXPR_FULL}, ?)"
            else:
                params.append(term.lower())
                return f"regexp_matches({SEARCH_TEXT_EXPR_FULL}, ?, 'i')"
        else:
            params.append(_lv(term))
            return f"CONTAINS({SEARCH_TEXT_EXPR_FULL}, ?)"

    term_clauses = [_term_clause(t) for t in text_terms]
    if mode == "AND":
        combined = f"({' AND '.join(term_clauses)})"
    elif mode == "OR":
        combined = f"({' OR '.join(term_clauses)})"
    elif mode == "NOT":
        combined = f"NOT ({' OR '.join(term_clauses)})"
    else:
        combined = f"({' AND '.join(term_clauses)})"

    if text_excl and mode != "NOT":
        combined = f"NOT {combined}"

    return combined, params
