#!/usr/bin/env python3
"""Browse per-relation Postgres I/O samples captured by bpftrace.

Reads an accumulated bpftrace log of the form:

    2026-09-16T14:23:01+0000
    @rbytes[16765, 16401]: 4218880
    @rbytes[16765, 16401.4]: 1024
    @wbytes[16765, 16402_fsm]: 8192

and presents a curses view: timestamps down the left, ranked relations on the
right, with filenode -> schema.relname resolution via psql.
"""

from __future__ import annotations

import argparse
import curses
import locale
import os
import re
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime

FS = "\x1f"
RS = "\x1e"

TS_PAT = rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?"
TS_RE = re.compile(b"^(" + TS_PAT + b")$")
# Non-greedy so a line holding several concatenated entries still splits, and
# so nested brackets like "[[signalfd], [signalfd]]" capture the whole key.
# The value is bounded rather than greedy: when a log shipper prefixes each
# line, a run-together log reads "...: 296" + "2026-09-16 ...", and a greedy
# \d+ silently parses that as 2962026.
VAL_END = rb"(?=[\s@]|\d{4}-\d{2}-\d{2}|$)"
ROW_PAT = rb"@(rbytes|wbytes)\[(.*?)\]:[ \t]*(\d+?)" + VAL_END
ROW_RE = re.compile(ROW_PAT)
# Timestamps and rows are matched anywhere in a line, because log shippers
# prefix each line (e.g. "2026-09-16 22:34:10 UTC BQ\t..."). The literal "T"
# between date and time is what keeps a wrapper's own space-separated
# timestamp from being mistaken for a sample boundary.
EVENT_RE = re.compile(b"(" + TS_PAT + b")|" + ROW_PAT)
RELFILE_RE = re.compile(r"^(\d+)(?:_(fsm|vm|init))?(?:\.(\d+))?$")
WAL_RE = re.compile(r"^[0-9A-F]{24}(?:\.(?:backup|partial))?$")
WAL_HIST_RE = re.compile(r"^[0-9A-F]{8}\.history$")
ANON_RE = re.compile(r"^\[(.*)\]$")
OID_MAX = 4294967295

CAT_REL, CAT_WAL, CAT_ANON, CAT_UNNAMED, CAT_OTHER = range(5)

TS_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S")

KIND_LETTER = {
    "r": "r", "p": "r", "i": "i", "I": "i",
    "t": "T", "m": "m", "S": "s", "v": "v", "f": "f",
}
WAL_KIND = "W"

CATALOG_SQL = """
SELECT c.oid::text,
       COALESCE(pg_relation_filenode(c.oid), 0)::text,
       n.nspname,
       c.relname,
       c.relkind::text,
       COALESCE(i.indrelid, tp.oid, 0)::text
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_index i ON i.indexrelid = c.oid
  LEFT JOIN pg_class tp ON tp.reltoastrelid = c.oid
 WHERE c.relkind = ANY (ARRAY['r','i','t','m','p','I','S'])
"""

DBLIST_SQL = "SELECT oid::text, datname FROM pg_database WHERE datallowconn"


def parse_ts(text):
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def human(n, width=9):
    if n == 0:
        return "-"
    units = ("B", "K", "M", "G", "T", "P")
    v = float(n)
    i = 0
    while v >= 1024.0 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    if i == 0:
        return "%dB" % int(v)
    if v < 10:
        return "%.2f%s" % (v, units[i])
    if v < 100:
        return "%.1f%s" % (v, units[i])
    return "%.0f%s" % (v, units[i])


def human_rate(n, seconds):
    if not seconds or seconds <= 0:
        return human(n)
    return human(n / seconds) + "/s"


def parse_size(text):
    text = text.strip().upper().replace("IB", "B")
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([BKMGT]?)B?$", text)
    if not m:
        raise ValueError("bad size: %s" % text)
    scale = {"": 1, "B": 1, "K": 1024, "M": 1024 ** 2,
             "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]
    return int(float(m.group(1)) * scale)


class Entry:
    __slots__ = ("ts", "ts_text", "offset", "total_r", "total_w")

    def __init__(self, ts, ts_text, offset):
        self.ts = ts
        self.ts_text = ts_text
        self.offset = offset
        self.total_r = 0
        self.total_w = 0

    @property
    def total(self):
        return self.total_r + self.total_w


class LogIndex:
    """One pass over the log records each sample's offset and gross volume.

    The per-sample totals come free during the scan and drive the activity bars,
    so spotting a spike never requires parsing every sample's rows.
    """

    def __init__(self, path):
        self.path = path
        self.entries = []
        self.scanned_bytes = 0
        self.skipped_rows = 0
        self._peaks = {"read": 0, "write": 0, "total": 0}
        self._cache = OrderedDict()

    def scan(self):
        self.entries = []
        self.skipped_rows = 0
        offset = 0
        cur = None
        with open(self.path, "rb") as fh:
            for line in fh:
                for m in EVENT_RE.finditer(line):
                    stamp = m.group(1)
                    if stamp is not None:
                        text = stamp.decode("ascii")
                        # anchor the sample at the timestamp itself, so any
                        # line prefix ahead of it stays out of the sample
                        cur = Entry(parse_ts(text), text, offset + m.start(1))
                        self.entries.append(cur)
                    elif cur is None:
                        self.skipped_rows += 1
                    else:
                        val = int(m.group(4))
                        if m.group(2) == b"rbytes":
                            cur.total_r += val
                        else:
                            cur.total_w += val
                offset += len(line)
        self.scanned_bytes = offset
        self._cache.clear()
        self._peaks = {
            "read": max((e.total_r for e in self.entries), default=0),
            "write": max((e.total_w for e in self.entries), default=0),
            "total": max((e.total for e in self.entries), default=0),
        }
        return len(self.entries)

    @property
    def max_total(self):
        return self._peaks["total"]

    def peak(self, metric):
        return self._peaks.get(metric, 0)

    def interval(self, i):
        if i + 1 < len(self.entries):
            a, b = self.entries[i].ts, self.entries[i + 1].ts
            if a and b:
                delta = (b - a).total_seconds()
                if delta > 0:
                    return delta
        for j in range(len(self.entries) - 1):
            a, b = self.entries[j].ts, self.entries[j + 1].ts
            if a and b:
                delta = (b - a).total_seconds()
                if delta > 0:
                    return delta
        return 30.0

    def sample(self, i):
        if i in self._cache:
            self._cache.move_to_end(i)
            return self._cache[i]
        start = self.entries[i].offset
        end = (self.entries[i + 1].offset
               if i + 1 < len(self.entries) else self.scanned_bytes)
        with open(self.path, "rb") as fh:
            fh.seek(start)
            blob = fh.read(max(0, end - start))
        rows = {}
        for m in ROW_RE.finditer(blob):
            key = split_key(m.group(2))
            slot = rows.get(key)
            if slot is None:
                slot = [0, 0]
                rows[key] = slot
            slot[0 if m.group(1) == b"rbytes" else 1] += int(m.group(3))
        self._cache[i] = rows
        while len(self._cache) > 48:
            self._cache.popitem(last=False)
        return rows

    def find(self, text):
        """Locate a sample from a full ISO prefix or a bare HH:MM:SS clock.

        The left column shows only the clock, so that is what gets typed, and
        comparing a bare clock against the whole ISO string always matched the
        very first sample.
        """
        text = (text or "").strip()
        if not text:
            return 0
        if re.match(r"^\d{1,2}(?::\d{1,2}){0,2}$", text):
            parts = (text.split(":") + ["00", "00"])[:3]
            want = ":".join(part.zfill(2) for part in parts)
            for i, e in enumerate(self.entries):
                if e.ts_text[11:19] >= want:
                    return i
            return len(self.entries) - 1
        for i, e in enumerate(self.entries):
            if e.ts_text >= text:
                return i
        return len(self.entries) - 1


def split_key(blob):
    """Classify a bpftrace map key into (dirname, name, category).

    Only the catalog can confirm that a numeric directory is really a database
    OID (it may be a PID under /proc), so CAT_REL means "shaped like a
    relation" and gets confirmed later.
    """
    text = blob.decode("utf-8", "replace")
    parts = [p.strip().strip('"') for p in text.split(",")]
    if len(parts) >= 2:
        dirname, fname = parts[-2], parts[-1]
    else:
        dirname, fname = "", (parts[0] if parts else "")

    if not fname and not dirname:
        return dirname, fname, CAT_UNNAMED

    # WAL is identified by filename, never by parent directory: with pg_wal
    # symlinked to its own volume the parent is that volume's real name.
    if WAL_RE.match(fname) or WAL_HIST_RE.match(fname):
        return dirname, fname, CAT_WAL

    m = ANON_RE.match(fname)
    if m:
        return dirname, m.group(1) or fname, CAT_ANON

    m = RELFILE_RE.match(fname)
    if m and (dirname == "global" or dirname.isdigit()):
        node = m.group(1)
        if len(node) <= 10 and int(node) <= OID_MAX:
            return dirname, node, CAT_REL
    return dirname, fname, CAT_OTHER


class RelInfo:
    __slots__ = ("oid", "schema", "name", "kind", "owner")

    def __init__(self, oid, schema, name, kind, owner):
        self.oid = oid
        self.schema = schema
        self.name = name
        self.kind = kind
        self.owner = owner

    @property
    def label(self):
        return "%s.%s" % (self.schema, self.name)


class Catalog:
    """Lazily pulls one database's whole relfilenode map per psql invocation."""

    def __init__(self, psql_extra, bootstrap_db, enabled=True):
        self.psql_extra = list(psql_extra or [])
        self.bootstrap_db = bootstrap_db
        self.enabled = enabled
        self.dbnames = None
        self.maps = {}
        self.status = "catalog: not loaded"
        self.failed = set()

    def _run(self, dbname, sql):
        cmd = ["psql", "-X", "-q", "-A", "-t", "-F", FS, "-R", RS,
               "-v", "ON_ERROR_STOP=1"]
        cmd += self.psql_extra
        if dbname:
            cmd += ["-d", dbname]
        cmd += ["-c", sql]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=180)
        if proc.returncode != 0:
            raise RuntimeError(
                proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["psql failed"])
        out = proc.stdout.decode("utf-8", "replace")
        rows = []
        for rec in out.split(RS):
            rec = rec.strip("\n")
            if rec:
                rows.append(rec.split(FS))
        return rows

    def _ensure_dbnames(self):
        if self.dbnames is not None or not self.enabled:
            return
        try:
            rows = self._run(self.bootstrap_db, DBLIST_SQL)
        except Exception as exc:
            self.enabled = False
            self.status = "catalog: psql failed (%s)" % str(exc)[:60]
            self.dbnames = {}
            return
        self.dbnames = {int(r[0]): r[1] for r in rows if len(r) >= 2}
        self.status = "catalog: %d databases" % len(self.dbnames)

    def _ensure_map(self, dbname):
        if dbname in self.maps:
            return self.maps[dbname]
        if dbname in self.failed or not self.enabled:
            return None
        try:
            rows = self._run(dbname, CATALOG_SQL)
        except Exception as exc:
            self.failed.add(dbname)
            self.status = "catalog: %s unresolved (%s)" % (dbname, str(exc)[:50])
            return None
        by_node = {}
        by_oid = {}
        for r in rows:
            if len(r) < 6:
                continue
            oid = int(r[0])
            node = int(r[1])
            info = RelInfo(oid, r[2], r[3], r[4], int(r[5]))
            by_oid[oid] = info
            if node:
                by_node[node] = info
        self.maps[dbname] = (by_node, by_oid)
        self.status = "catalog: %s (%d relations)" % (dbname, len(by_node))
        return self.maps[dbname]

    def is_database(self, dirname):
        """Is this directory really a database OID dir (not a /proc PID dir)?"""
        if dirname == "global":
            return True
        if not dirname.isdigit() or len(dirname) > 10:
            return False
        if int(dirname) > OID_MAX:
            return False
        if not self.enabled:
            return True
        self._ensure_dbnames()
        if not self.dbnames:
            return True
        return int(dirname) in self.dbnames

    def dbname_for(self, dirname):
        if dirname.isdigit():
            self._ensure_dbnames()
            return (self.dbnames or {}).get(int(dirname))
        if dirname == "global":
            return self.bootstrap_db
        return None

    def lookup(self, dirname, base):
        if not self.enabled:
            return None, None
        dbname = self.dbname_for(dirname)
        if not dbname:
            return None, None
        maps = self._ensure_map(dbname)
        if not maps:
            return dbname, None
        try:
            node = int(base)
        except ValueError:
            return dbname, None
        return dbname, maps[0].get(node)

    def root_of(self, dbname, info):
        maps = self.maps.get(dbname)
        if not maps:
            return info
        by_oid = maps[1]
        cur = info
        for _ in range(4):
            if not cur.owner:
                break
            nxt = by_oid.get(cur.owner)
            if nxt is None or nxt.oid == cur.oid:
                break
            cur = nxt
        return cur


class Row:
    __slots__ = ("db", "rel", "kind", "r", "w", "pr", "pw", "pt", "rank")

    def __init__(self, db, rel, kind):
        self.db = db
        self.rel = rel
        self.kind = kind
        self.r = 0
        self.w = 0
        self.pr = self.pw = self.pt = 0.0
        self.rank = 0

    @property
    def total(self):
        return self.r + self.w


class View:
    SORTS = {"r": "read", "w": "write", "t": "total"}
    PEER_SCOPES = ("sample", "database")

    def __init__(self, index, catalog, opts):
        self.index = index
        self.catalog = catalog
        self.cur = max(0, min(opts.start, len(index.entries) - 1))
        self.sel = 0
        self.row_top = 0
        self.ts_top = 0
        self.sort = opts.sort
        self.min_bytes = opts.min_bytes
        self.min_pct = opts.min_pct
        self.rollup = opts.rollup
        self.names = not opts.no_names
        self.rate = False
        self.peer_scope = self.PEER_SCOPES.index(
            getattr(opts, "peer_scope", "sample"))
        self.focus = None
        self._series = None
        self._series_sig = None
        self.filter_src = getattr(opts, "filter", None) or ""
        self.filter_re = re.compile(self.filter_src, re.I) if self.filter_src else None
        self.message = ""
        self._cache_key = None
        self._rows = []
        self._stats = {}

    # ---- data ----------------------------------------------------------

    def state_key(self):
        return (self.cur, self.sort, self.min_bytes, self.min_pct,
                self.rollup, self.names, self.peer_scope, self.filter_src,
                self.focus)

    def rows(self):
        key = self.state_key()
        if key == self._cache_key:
            return self._rows, self._stats
        self._rows, self._stats = self._build()
        self._cache_key = key
        return self._rows, self._stats

    def classify(self, dirname, base, cat):
        """Map a parsed key to the (database, relation, kind) shown in the table."""
        if cat == CAT_WAL:
            return (dirname or "wal",
                    "wal/*" if self.rollup else "wal/%s" % base, WAL_KIND)
        if cat == CAT_ANON:
            return "anon", base, "-"
        if cat == CAT_UNNAMED:
            return "?", "(unnamed)", "-"

        if cat == CAT_REL:
            if self.names and self.catalog.is_database(dirname):
                dbname, info = self.catalog.lookup(dirname, base)
                db = dbname or dirname
                if info is None:
                    return db, "#%s" % base, "?"
                if self.rollup:
                    info = self.catalog.root_of(dbname, info)
                return db, info.label, KIND_LETTER.get(info.kind, info.kind)
            if self.names:
                return dirname, "%s/%s" % (dirname, base), "-"
            return dirname, base, "?"

        db = dirname or "?"
        if self.names and self.catalog.is_database(dirname):
            db = self.catalog.dbname_for(dirname) or dirname
        return db, ("*" if self.rollup else base), "-"

    def _build(self):
        sample = self.index.sample(self.cur)
        agg = {}
        for (dirname, base, cat), (rb, wb) in sample.items():
            db, label, kind = self.classify(dirname, base, cat)
            k = (db, label, kind)
            row = agg.get(k)
            if row is None:
                row = Row(db, label, kind)
                agg[k] = row
            row.r += rb
            row.w += wb

        rows = list(agg.values())
        tot_r = sum(x.r for x in rows)
        tot_w = sum(x.w for x in rows)
        per_db = {}
        for x in rows:
            d = per_db.setdefault(x.db, [0, 0])
            d[0] += x.r
            d[1] += x.w

        scope = self.PEER_SCOPES[self.peer_scope]
        for x in rows:
            if scope == "database":
                dr, dw = per_db[x.db]
            else:
                dr, dw = tot_r, tot_w
            x.pr = 100.0 * x.r / dr if dr else 0.0
            x.pw = 100.0 * x.w / dw if dw else 0.0
            denom = (dr + dw)
            x.pt = 100.0 * x.total / denom if denom else 0.0

        metric = self.SORTS[self.sort]
        abs_of = {"read": lambda x: x.r, "write": lambda x: x.w,
                  "total": lambda x: x.total}[metric]
        pct_of = {"read": lambda x: x.pr, "write": lambda x: x.pw,
                  "total": lambda x: x.pt}[metric]

        # Rank across every row in the sample, then hide: a relation keeps the
        # rank it would have had unfiltered, so gaps show what is being hidden.
        rows.sort(key=abs_of, reverse=True)
        for n, x in enumerate(rows, 1):
            x.rank = n

        hidden = 0
        hidden_bytes = 0
        filtered = 0
        if self.focus is not None:
            kept = [x for x in rows if (x.db, x.rel, x.kind) == self.focus]
            if not kept:
                # idle in this sample: a zero row keeps the timeline continuous
                kept = [Row(*self.focus)]
            for x in rows:
                if (x.db, x.rel, x.kind) != self.focus:
                    hidden += 1
                    hidden_bytes += abs_of(x)
        else:
            kept = []
            for x in rows:
                if self.filter_re and not self.filter_re.search(
                        "%s.%s" % (x.db, x.rel)):
                    filtered += 1
                    continue
                if abs_of(x) < self.min_bytes or pct_of(x) < self.min_pct:
                    hidden += 1
                    hidden_bytes += abs_of(x)
                    continue
                kept.append(x)

        stats = {
            "tot_r": tot_r, "tot_w": tot_w, "relations": len(rows),
            "vis_r": sum(x.r for x in kept), "vis_w": sum(x.w for x in kept),
            "visible": len(kept), "hidden": hidden,
            "hidden_bytes": hidden_bytes, "filtered": filtered,
            "metric": metric, "scope": scope,
            "interval": self.index.interval(self.cur),
        }
        return kept, stats

    # ---- rendering -----------------------------------------------------

    def ensure_series(self, scr=None):
        """Per-sample totals for the focused relation, driving the left bars.

        This is the one operation that must touch every sample, which the lazy
        index otherwise avoids, so it is computed once per focus change and
        cached against the settings that affect classification.
        """
        if self.focus is None:
            self._series = None
            self._series_sig = None
            return None
        sig = (self.focus, self.rollup, self.names)
        if sig == self._series_sig:
            return self._series
        count = len(self.index.entries)
        series = []
        for i in range(count):
            if scr is not None and count > 250 and i % 128 == 0:
                srows, scols = scr.getmaxyx()
                safe_addnstr(scr, srows - 1, 0,
                             "scanning sample %d/%d for %s..."
                             % (i, count, self.focus[1]), scols - 1,
                             curses.A_BOLD)
                scr.refresh()
            rsum = wsum = 0
            for (dirname, base, cat), (rb, wb) in self.index.sample(i).items():
                if self.classify(dirname, base, cat) == self.focus:
                    rsum += rb
                    wsum += wb
            series.append((rsum, wsum))
        self._series = series
        self._series_sig = sig
        return series

    def fmt(self, n, stats):
        if self.rate:
            return human_rate(n, stats["interval"])
        return human(n)

    def draw(self, scr, ascii_bars):
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 8 or w < 48:
            safe_addnstr(scr, 0, 0, "terminal too small", w - 1)
            scr.noutrefresh()
            return
        rows, stats = self.rows()
        if w >= 105:
            left = 29
        elif w >= 89:
            left = 23
        elif w >= 77:
            left = 20
        else:
            left = 17
        body = h - 3
        self.draw_header(scr, w, stats)
        self.draw_left(scr, 3, body, left, ascii_bars, stats)
        self.draw_table(scr, 3, body, left + 1, w - left - 2, rows, stats)
        bottom = ""
        if self.focus is not None:
            bottom = "focus: %s   Enter or Esc to leave" % self.focus[1]
            if self.message:
                bottom += "   |   " + self.message
        elif self.message:
            bottom = self.message
        if bottom:
            safe_addnstr(scr, h - 1, 0, bottom, w - 1, curses.A_BOLD)
        scr.noutrefresh()

    def draw_header(self, scr, w, stats):
        e = self.index.entries[self.cur]
        segs = [("%s  sample %d/%d  "
                 % (e.ts_text, self.cur + 1, len(self.index.entries)),
                 curses.A_BOLD)]
        for label, vis, tot, scaled in (
                ("read", stats["vis_r"], stats["tot_r"], True),
                ("write", stats["vis_w"], stats["tot_w"], True),
                ("relations", stats["visible"], stats["relations"], False)):
            if scaled:
                shown = "%s/%s" % (self.fmt(vis, stats), self.fmt(tot, stats))
            else:
                shown = "%d/%d" % (vis, tot)
            segs.append((label + " ", curses.A_BOLD))
            segs.append((shown, ratio_attr(vis, tot)))
            segs.append(("  ", curses.A_NORMAL))
        put_segments(scr, 0, 0, w - 1, segs)
        bits = ["rank:%s" % stats["metric"], "peers:%s" % stats["scope"],
                "rollup:%s" % ("on" if self.rollup else "off"),
                "resolve:%s" % ("on" if self.names else "off"),
                "units:%s" % ("rate" if self.rate else "bytes"),
                "cut:%s/%.2g%%" % (human(self.min_bytes), self.min_pct)]
        if self.filter_src:
            bits.append("/%s" % self.filter_src)
        if self.focus is not None:
            bits.append("focus:%s" % trunc(self.focus[1], 24))
        bits.append(self.catalog.status)
        bits.append("?=help q=quit")
        safe_addnstr(scr, 1, 0, "  ".join(bits), w - 1, curses.A_DIM)

    def draw_left(self, scr, top, height, width, ascii_bars, stats):
        n = len(self.index.entries)
        if self.cur < self.ts_top:
            self.ts_top = self.cur
        elif self.cur >= self.ts_top + height:
            self.ts_top = self.cur - height + 1
        self.ts_top = max(0, min(self.ts_top, max(0, n - height)))
        metric = stats["metric"]
        pick = {"read": 0, "write": 1}.get(metric)
        series = self._series if self.focus is not None else None
        if series:
            if pick is None:
                values = [rb + wb for (rb, wb) in series]
            else:
                values = [pair_[pick] for pair_ in series]
            peak = max(values) or 1
        else:
            values = None
            peak = self.index.peak(metric) or 1
        bar_w = max(0, width - 17)
        label = metric + ("/s" if self.rate else "")
        tint = pair(C_PANEL) if PANEL_OK else 0
        safe_addnstr(scr, top - 1, 0,
                     ("time".ljust(9) + label.rjust(7)).ljust(width), width,
                     curses.A_UNDERLINE | tint)
        # the gutter separates the timeline from the table; the active
        # sample gets a pointer so it reads as "this drives the table"
        # rather than as a row belonging to the table row beside it
        vline = "|" if ascii_bars else curses.ACS_VLINE
        marker = ">" if ascii_bars else "▶"
        for y in range(top - 1, top + height):
            try:
                scr.addch(y, width, vline)
            except curses.error:
                pass
        for i in range(height):
            idx = self.ts_top + i
            if idx >= n:
                if tint:
                    safe_addnstr(scr, top + i, 0, " " * width, width, tint)
                continue
            e = self.index.entries[idx]
            if values is not None and idx < len(values):
                val = values[idx]
            elif metric == "read":
                val = e.total_r
            elif metric == "write":
                val = e.total_w
            else:
                val = e.total
            # reverse video is reserved for the table cursor; the active
            # sample instead drops the panel tint and gains the pointer
            selected = idx == self.cur
            bg = 0 if selected else tint
            bold = curses.A_BOLD if selected else curses.A_NORMAL
            bar = render_bar(val, peak, bar_w, ascii_bars)
            put_segments(scr, top + i, 0, width, [
                (e.ts_text[11:19], bold | bg),
                (" %7s " % self.fmt(val, stats)[:7], bold | bg),
                (bar.ljust(bar_w) if bg else bar, bg),
            ])
            if selected:
                safe_addnstr(scr, top + i, width, marker, 1, curses.A_BOLD)

    def draw_table(self, scr, top, height, x0, width, rows, stats):
        show_total = width >= 74
        show_db = width >= 58
        num = 9
        pct = 7
        fixed = 5 + (14 if show_db else 0) + 2 + (num + pct) * 2
        if show_total:
            fixed += num + pct
        relw = max(14, width - fixed - 1)
        metric = stats["metric"]
        hot = {"read": 0, "write": 1, "total": 2}[metric]
        base_head = curses.A_UNDERLINE
        head = [("   # ", base_head)]
        if show_db:
            head.append(("DATABASE".ljust(14), base_head))
        stamp = self.index.entries[self.cur].ts_text[11:19]
        head.append((trunc("RELATION @ " + stamp, relw).ljust(relw) + " K",
                     base_head))
        for j, (wide, thin) in enumerate((("READ", "%R"), ("WRITE", "%W"),
                                          ("TOTAL", "%T"))):
            if j == 2 and not show_total:
                continue
            head.append((wide.rjust(num) + thin.rjust(pct),
                         base_head | (curses.A_BOLD if j == hot else 0)))
        used = sum(len(t) for t, _ in head)
        if used < width:
            head.append((" " * (width - used), base_head))
        put_segments(scr, top - 1, x0, width, head)

        if self.sel >= len(rows):
            self.sel = max(0, len(rows) - 1)
        if self.sel < self.row_top:
            self.row_top = self.sel
        elif self.sel >= self.row_top + height:
            self.row_top = self.sel - height + 1
        self.row_top = max(0, min(self.row_top, max(0, len(rows) - height)))

        for i in range(height):
            idx = self.row_top + i
            if idx >= len(rows):
                break
            r = rows[idx]
            base = curses.A_REVERSE if idx == self.sel else curses.A_NORMAL
            segs = [("%4s " % (r.rank if r.rank else "-"), base)]
            if show_db:
                segs.append((trunc(r.db, 13).ljust(14), base))
            segs.append((trunc(r.rel, relw).ljust(relw) + " " + r.kind, base))
            for j, (value, percent) in enumerate(((r.r, r.pr), (r.w, r.pw),
                                                  (r.total, r.pt))):
                if j == 2 and not show_total:
                    continue
                segs.append((self.fmt(value, stats).rjust(num) + pctstr(percent).rjust(pct),
                             base | (curses.A_BOLD if j == hot else 0)))
            used = sum(len(t) for t, _ in segs)
            if used < width:
                segs.append((" " * (width - used), base))
            put_segments(scr, top + i, x0, width, segs)


C_GREEN, C_ORANGE, C_RED, C_PANEL = 1, 2, 3, 4
COLORS_OK = False
PANEL_OK = False


def light_background():
    """COLORFGBG is "fg;bg" (sometimes "fg;x;bg"); 7 and 15 are light."""
    bg = os.environ.get("COLORFGBG", "").split(";")[-1]
    return bg in ("7", "15")


def setup_colors():
    """Best-effort colour pairs; the UI stays legible without them."""
    global COLORS_OK, PANEL_OK
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:
        return
    if not curses.has_colors():
        return
    orange = 208 if curses.COLORS >= 256 else curses.COLOR_YELLOW
    try:
        curses.init_pair(C_GREEN, curses.COLOR_GREEN, -1)
        curses.init_pair(C_ORANGE, orange, -1)
        curses.init_pair(C_RED, curses.COLOR_RED, -1)
    except curses.error:
        return
    COLORS_OK = True
    # a subtle tint for the timeline panel needs a 256-colour palette;
    # without one the gutter line alone separates the panes
    if curses.COLORS >= 256:
        try:
            curses.init_pair(C_PANEL, -1, 254 if light_background() else 236)
            PANEL_OK = True
        except curses.error:
            pass


def pair(n):
    return curses.color_pair(n) if COLORS_OK else 0


def ratio_attr(visible, total):
    """Green when most of the value is on screen, red when most is hidden."""
    if total <= 0:
        return curses.A_BOLD
    frac = float(visible) / total
    if frac >= 0.8:
        return curses.A_BOLD | pair(C_GREEN)
    if frac >= 0.5:
        return curses.A_BOLD | pair(C_ORANGE)
    return curses.A_BOLD | pair(C_RED)


def put_segments(scr, y, x0, width, segments):
    x = x0
    limit = x0 + width
    for text, attr in segments:
        if not text or x >= limit:
            continue
        safe_addnstr(scr, y, x, text, limit - x, attr)
        x += len(text)
    return x


def safe_addnstr(scr, y, x, text, n, attr=curses.A_NORMAL):
    try:
        scr.addnstr(y, x, text, n, attr)
    except curses.error:
        pass


def pctstr(v):
    if v <= 0:
        return "-"
    if v >= 99.95:
        return "100%"
    if v < 0.1:
        return "<0.1%"
    return "%.1f%%" % v


def trunc(text, n):
    if len(text) <= n:
        return text
    if n <= 3:
        return text[:n]
    keep = n - 1
    return text[:keep - keep // 2] + "~" + text[len(text) - keep // 2:]


BLOCKS = " ▏▎▍▌▋▊▉█"


def render_bar(value, peak, width, ascii_bars):
    if width <= 0 or peak <= 0 or value <= 0:
        return ""
    frac = min(1.0, float(value) / peak)
    if ascii_bars:
        return "#" * max(1, int(round(frac * width)))
    cells = frac * width
    full = int(cells)
    rem = cells - full
    out = "█" * full
    if full < width and rem > 0.06:
        out += BLOCKS[min(len(BLOCKS) - 1, int(rem * 8) + 1)]
    return out or BLOCKS[1]


HELP = [
    "navigation",
    "  j k Up Down       move relation selection",
    "  PgUp PgDn         page relation list",
    "  h l Left Right    previous / next sample",
    "  [ ]               jump back / forward 10 samples",
    "  g G               first / last sample",
    "  :                 jump to time (14:23 or 2026-09-16T14:2)",
    "",
    "focus",
    "  Enter             isolate the selected relation; the left bars",
    "                    are rebuilt from that relation's own history",
    "  Enter Esc         leave focus",
    "",
    "ranking",
    "  r w t             rank by read / write / total bytes",
    "  p                 peer scope for % columns (sample/db)",
    "",
    "display",
    "  o                 toggle rollup of indexes, TOAST and forks",
    "  n                 toggle filenode -> schema.relname resolution",
    "  u                 toggle bytes / bytes-per-second",
    "  m                 set minimum absolute cutoff (e.g. 4M)",
    "  %                 set minimum percentage cutoff",
    "  /                 filter relations by regex (empty clears)",
    "                    Up recalls the previous filter for editing",
    "                    ^U ^W ^K ^A ^E work while typing",
    "",
    "other",
    "  Ctrl-R            re-index the log (picks up new samples)",
    "  ? q               help / quit",
]


def show_help(scr):
    """Scrollable help: the key list is taller than an 80x24 terminal."""
    h, w = scr.getmaxyx()
    height = min(h - 2, len(HELP) + 3)
    width = min(w - 2, max(len(line) for line in HELP) + 6)
    page = max(1, height - 3)
    top = 0
    win = curses.newwin(height, width, (h - height) // 2, (w - width) // 2)
    win.keypad(True)
    last = max(0, len(HELP) - page)
    while True:
        win.erase()
        win.box()
        for i in range(page):
            j = top + i
            if j >= len(HELP):
                break
            line = HELP[j]
            attr = (curses.A_BOLD if line and not line.startswith(" ")
                    else curses.A_NORMAL)
            safe_addnstr(win, i + 1, 2, line, width - 4, attr)
        if len(HELP) > page:
            hint = ("%d-%d of %d   j k arrows scroll, other key closes"
                    % (top + 1, min(top + page, len(HELP)), len(HELP)))
        else:
            hint = "any key closes"
        safe_addnstr(win, height - 2, 2, hint, width - 4, curses.A_DIM)
        win.refresh()
        ch = win.getch()
        if ch in (curses.KEY_DOWN, ord("j")):
            top = min(last, top + 1)
        elif ch in (curses.KEY_UP, ord("k")):
            top = max(0, top - 1)
        elif ch in (curses.KEY_NPAGE, ord(" ")):
            top = min(last, top + page)
        elif ch == curses.KEY_PPAGE:
            top = max(0, top - page)
        elif ch == curses.KEY_HOME:
            top = 0
        elif ch == curses.KEY_END:
            top = last
        else:
            return


def prompt(scr, label, initial="", recall=""):
    h, w = scr.getmaxyx()
    buf = list(initial)
    pos = len(buf)
    try:
        curses.curs_set(2)
    except curses.error:
        pass
    try:
        while True:
            text = label + "".join(buf)
            scr.move(h - 1, 0)
            scr.clrtoeol()
            safe_addnstr(scr, h - 1, 0, text, w - 1, curses.A_BOLD)
            # a reversed cell is drawn as the caret: a terminal cursor that is
            # dark, or the same colour as the text, is invisible here
            caret = min(len(label) + pos, max(0, w - 2))
            under = buf[pos] if pos < len(buf) else " "
            safe_addnstr(scr, h - 1, caret, under, 1,
                         curses.A_REVERSE | curses.A_BOLD)
            scr.move(h - 1, caret)
            scr.refresh()
            ch = scr.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                return "".join(buf)
            if ch in (27, 3):                                  # Esc, ^C
                return None
            elif ch in (curses.KEY_BACKSPACE, 127, 8):         # ^H
                if pos > 0:
                    del buf[pos - 1]
                    pos -= 1
            elif ch in (curses.KEY_DC, 4):                     # ^D
                if pos < len(buf):
                    del buf[pos]
            elif ch == 21:                                     # ^U
                del buf[:pos]
                pos = 0
            elif ch == 11:                                     # ^K
                del buf[pos:]
            elif ch == 23:                                     # ^W
                i = pos
                while i > 0 and buf[i - 1].isspace():
                    i -= 1
                while i > 0 and not buf[i - 1].isspace():
                    i -= 1
                del buf[i:pos]
                pos = i
            elif ch in (1, curses.KEY_HOME):                   # ^A
                pos = 0
            elif ch in (5, curses.KEY_END):                    # ^E
                pos = len(buf)
            elif ch in (2, curses.KEY_LEFT):                   # ^B
                pos = max(0, pos - 1)
            elif ch in (6, curses.KEY_RIGHT):                  # ^F
                pos = min(len(buf), pos + 1)
            elif ch in (16, curses.KEY_UP) and recall:          # ^P recall
                buf = list(recall)
                pos = len(buf)
            elif ch in (14, curses.KEY_DOWN):                   # ^N
                buf = []
                pos = 0
            elif 32 <= ch < 127:
                buf.insert(pos, chr(ch))
                pos += 1
    finally:
        try:
            curses.curs_set(0)
        except curses.error:
            pass


def run_ui(scr, index, catalog, opts, ascii_bars):
    setup_colors()
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    scr.keypad(True)
    view = View(index, catalog, opts)
    while True:
        view.ensure_series(scr)
        view.draw(scr, ascii_bars)
        curses.doupdate()
        ch = scr.getch()
        view.message = ""
        h, _ = scr.getmaxyx()
        page = max(1, h - 6)
        n = len(index.entries)

        if ch in (ord("q"), ord("Q")):
            return
        elif ch == curses.KEY_RESIZE:
            continue
        elif ch in (10, 13, curses.KEY_ENTER):
            if view.focus is not None:
                view.focus = None
                view.message = "focus cleared"
            else:
                picked, _ = view.rows()
                if picked and view.sel < len(picked):
                    row = picked[view.sel]
                    view.focus = (row.db, row.rel, row.kind)
                    view.sel = 0
        elif ch == 27:
            if view.focus is not None:
                view.focus = None
                view.message = "focus cleared"
        elif ch in (ord("j"), curses.KEY_DOWN):
            view.sel += 1
        elif ch in (ord("k"), curses.KEY_UP):
            view.sel = max(0, view.sel - 1)
        elif ch == curses.KEY_NPAGE:
            view.sel += page
        elif ch == curses.KEY_PPAGE:
            view.sel = max(0, view.sel - page)
        elif ch == curses.KEY_HOME:
            view.sel = 0
        elif ch in (ord("l"), curses.KEY_RIGHT):
            view.cur = min(n - 1, view.cur + 1)
            view.sel = 0
        elif ch in (ord("h"), curses.KEY_LEFT):
            view.cur = max(0, view.cur - 1)
            view.sel = 0
        elif ch == ord("]"):
            view.cur = min(n - 1, view.cur + 10)
            view.sel = 0
        elif ch == ord("["):
            view.cur = max(0, view.cur - 10)
            view.sel = 0
        elif ch == ord("g"):
            view.cur = 0
            view.sel = 0
        elif ch == ord("G"):
            view.cur = n - 1
            view.sel = 0
        elif ch == ord(":"):
            text = prompt(scr, "jump to time (14:23 or 2026-09-16T14:2): ")
            if text:
                view.cur = index.find(text)
                view.sel = 0
                view.message = "jumped to %s" % index.entries[view.cur].ts_text
        elif ch in tuple(ord(c) for c in "rwt"):
            view.sort = chr(ch)
            view.sel = 0
        elif ch == ord("p"):
            view.peer_scope = (view.peer_scope + 1) % len(View.PEER_SCOPES)
            view.sel = 0
        elif ch == ord("o"):
            view.rollup = not view.rollup
            view.sel = 0
        elif ch == ord("n"):
            view.names = not view.names
            view.sel = 0
        elif ch == ord("u"):
            view.rate = not view.rate
        elif ch == ord("m"):
            text = prompt(scr, "min bytes (e.g. 4M, 0 to clear): ")
            if text is not None:
                try:
                    view.min_bytes = parse_size(text) if text.strip() else 0
                except ValueError as exc:
                    view.message = str(exc)
        elif ch == ord("%"):
            text = prompt(scr, "min percent (e.g. 1.5, 0 to clear): ")
            if text is not None:
                try:
                    view.min_pct = float(text) if text.strip() else 0.0
                except ValueError:
                    view.message = "bad percentage"
        elif ch == ord("/"):
            text = prompt(scr, "filter regex (empty clears): ", "",
                          view.filter_src)
            if text is not None:
                if text.strip():
                    try:
                        view.filter_re = re.compile(text, re.I)
                        view.filter_src = text
                    except re.error as exc:
                        view.message = "bad regex: %s" % exc
                else:
                    view.filter_re = None
                    view.filter_src = ""
                view.sel = 0
        elif ch == 18:  # Ctrl-R
            before = len(index.entries)
            count = index.scan()
            view.cur = min(view.cur, count - 1)
            view._cache_key = None
            view.message = "re-indexed: %d samples (+%d)" % (
                count, count - before)
        elif ch in (ord("?"),):
            show_help(scr)


def dump(index, catalog, opts, which):
    if which.isdigit():
        i = max(0, min(int(which) - 1, len(index.entries) - 1))
    else:
        i = index.find(which)
    view = View(index, catalog, opts)
    view.cur = i
    rows, stats = view.rows()
    e = index.entries[i]
    print("%s  sample %d/%d  read %s/%s  write %s/%s  relations %d/%d" % (
        e.ts_text, i + 1, len(index.entries),
        human(stats["vis_r"]), human(stats["tot_r"]),
        human(stats["vis_w"]), human(stats["tot_w"]),
        stats["visible"], stats["relations"]))
    print("%-5s %-14s %-42s %-2s %10s %8s %10s %8s %10s %8s" % (
        "#", "DATABASE", "RELATION", "K", "READ", "%R", "WRITE", "%W",
        "TOTAL", "%T"))
    for r in rows[:opts.dump_limit]:
        print("%-5d %-14s %-42s %-2s %10s %8s %10s %8s %10s %8s" % (
            r.rank, trunc(r.db, 14), trunc(r.rel, 42), r.kind,
            human(r.r), pctstr(r.pr), human(r.w), pctstr(r.pw),
            human(r.total), pctstr(r.pt)))
    print("%d shown, %d hidden by cutoff (%s)" % (
        len(rows), stats["hidden"], human(stats["hidden_bytes"])))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Browse bpftrace per-relation Postgres I/O samples.")
    ap.add_argument("logfile")
    ap.add_argument("--psql-arg", action="append", default=[], metavar="ARG",
                    help="extra argument passed to psql (repeatable), "
                         "e.g. --psql-arg -hdb1 --psql-arg -Upostgres")
    ap.add_argument("--dbname", default=os.environ.get("PGDATABASE", "postgres"),
                    help="database used to list databases and shared catalogs")
    ap.add_argument("--no-names", action="store_true",
                    help="skip psql entirely, show raw filenodes")
    ap.add_argument("--min-bytes", default="64K",
                    help="initial absolute cutoff (default 64K)")
    ap.add_argument("--min-pct", type=float, default=0.0,
                    help="initial percentage cutoff")
    ap.add_argument("--filter", metavar="REGEX",
                    help="only show relations matching REGEX (db.schema.rel)")
    ap.add_argument("--sort", default="t", choices=list(View.SORTS),
                    help="initial ranking key: read, write or total "
                         "(default t)")
    ap.add_argument("--peer-scope", default="sample",
                    choices=list(View.PEER_SCOPES),
                    help="denominator for the %%-of-peers columns "
                         "(default sample)")
    ap.add_argument("--no-rollup", dest="rollup", action="store_false",
                    default=True, help="start with rollup disabled")
    ap.add_argument("--start", type=int, default=0,
                    help="sample number to open on (1-based)")
    ap.add_argument("--list", action="store_true",
                    help="print the sample index and exit")
    ap.add_argument("--dump", metavar="SAMPLE",
                    help="print one sample as text and exit "
                         "(sample number or timestamp prefix)")
    ap.add_argument("--dump-limit", type=int, default=40)
    opts = ap.parse_args(argv)

    try:
        opts.min_bytes = parse_size(opts.min_bytes)
    except ValueError as exc:
        ap.error(str(exc))
    opts.start = max(0, opts.start - 1) if opts.start else 0

    index = LogIndex(opts.logfile)
    count = index.scan()
    if not count:
        sys.stderr.write("no samples found in %s\n"
                         "(expected bpftrace output with ISO timestamp lines "
                         "and @rbytes/@wbytes rows)\n" % opts.logfile)
        return 2
    if index.skipped_rows:
        sys.stderr.write("note: ignored %d rows before the first timestamp\n"
                         % index.skipped_rows)

    catalog = Catalog(opts.psql_arg, opts.dbname, enabled=not opts.no_names)

    if opts.list:
        for i, e in enumerate(index.entries, 1):
            print("%5d  %s  read %9s  write %9s" % (
                i, e.ts_text, human(e.total_r), human(e.total_w)))
        return 0
    if opts.dump:
        dump(index, catalog, opts, opts.dump)
        return 0

    locale.setlocale(locale.LC_ALL, "")
    encoding = locale.getpreferredencoding(False) or ""
    ascii_bars = "utf" not in encoding.lower().replace("-", "")
    try:
        curses.wrapper(run_ui, index, catalog, opts, ascii_bars)
    except curses.error as exc:
        sys.stderr.write(
            "could not start the display: %s\n"
            "Set TERM to a terminal your terminfo knows (TERM=xterm works "
            "almost everywhere), or use --list / --dump for plain text.\n"
            % exc)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
