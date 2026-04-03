#!/usr/bin/env python3
"""
MDF/PCAP/ASCII Converter GUI — two-pane layout with scrollable panes.

Vector ASC post-processing (after MDF→ASCII):
  - Parses filter: can.id / id (decimal or 0x…), busid (integer).
  - Selects .asc files by busid (DG index in filename, substring, or file order).
  - Filters CAN lines by ID; FlexRay-null removal only on wide rows (≥6 columns), not plain CAN tab traces.
  - Preserves Vector-style error lines (ErrorFrame / error column); CAN_ErrorFrame export is fixed in mdf2ascii.
  - Writes bus mapping table to a sidecar file when enabled.
"""

import glob
import json
import os
import re
import subprocess
import time
import tkinter as tk
from typing import Optional
from tkinter import ttk, filedialog, messagebox

# Colors
ORANGE = "#E85D04"
BG_WHITE = "#FFFFFF"
BG_LIGHT_GRAY = "#F5F5F5"
BORDER_GRAY = "#E0E0E0"
TEXT_DARK = "#333333"
BLUE_HIGHLIGHT = "#E8E0F5"  # light purple for CAN cell (Vector-style)
FILTER_PLACEHOLDER = "e.g. ((busid == 364) and (can.id == 0x1A1))"

# Writer formats: (display_label, exe_args, input_extensions, output_ext)
WRITER_FORMATS = [
    ("PCAP format", ["--mdf2pcap"], [".mf4", ".mdf"], ".pcap"),
    ("Vector ASC", [], [".mf4", ".mdf"], ".asc"),
    ("PCAPNG format", ["--mdf2pcapng"], [".mf4", ".mdf"], ".pcapng"),
    ("MDF format", ["--pcap2mdf"], [".pcap"], ".mf4"),
    ("MDF format (PCAPNG)", ["--pcapng2mdf"], [".pcapng"], ".mf4"),
]

DEFAULT_OUTPUT_DIR = r"D:\yesmine\3eme\PFE\fichiers\fichiers-convertis"


def find_exe():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    for exe in [
        os.path.join(project_root, "mdf2ascii.exe"),
        os.path.join(project_root, "dist", "mdf2ascii.exe"),
        os.path.join(project_root, "build", "mdf2ascii.exe"),
        os.path.join(project_root, "build", "Release", "mdf2ascii.exe"),
    ]:
        if os.path.isfile(exe):
            return exe
    return None


def get_input_ext(path):
    return os.path.splitext(path)[1].lower()


def get_writer_config(label, input_ext):
    for fmt_label, args, in_exts, out_ext in WRITER_FORMATS:
        if fmt_label == label and input_ext in in_exts:
            return args, out_ext
    return None


def make_scrollable(parent, bg=BG_WHITE):
    """Return (outer_frame, inner_frame) — inner_frame scrolls vertically."""
    outer = tk.Frame(parent, bg=bg)
    canvas = tk.Canvas(outer, bg=bg, highlightthickness=0, borderwidth=0)
    vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg=bg)

    win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=vsb.set)

    def _on_inner_configure(_event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        try:
            canvas.itemconfigure(win_id, width=max(canvas.winfo_width(), 1))
        except tk.TclError:
            pass

    def _on_canvas_configure(event):
        if event.width > 1:
            canvas.itemconfigure(win_id, width=event.width)

    inner.bind("<Configure>", _on_inner_configure)
    canvas.bind("<Configure>", _on_canvas_configure)

    def _wheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    canvas.bind("<MouseWheel>", _wheel)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.RIGHT, fill=tk.Y)
    return outer, inner


def _normalize_hex_id(s: str) -> str:
    s = s.strip().rstrip(")").strip()
    try:
        v = int(s, 0)
        return "0x" + format(v, "x")
    except ValueError:
        return s.lower()


def _parse_vector_filter_expression(text: str):
    """
    Extract comparisons: can.id == …, id == … (not after 'can.'), busid == … (integer).
    RHS may be decimal (417) or hex (0x1a1).

    Returns dict: can_ids (set of normalized 0x…), busids (set of int), note (str).
    """
    empty = {"can_ids": set(), "busids": set(), "note": ""}
    if not text or text.strip() == FILTER_PLACEHOLDER:
        return empty
    s = text.strip()
    can_ids = set()
    busids = set()

    def _add_can(rhs: str):
        rhs = rhs.strip().rstrip(")").strip()
        try:
            can_ids.add(_normalize_hex_id(rhs))
        except Exception:
            pass

    for m in re.finditer(r"can\.id\s*==\s*([^)&\s]+)", s, re.IGNORECASE):
        _add_can(m.group(1))
    for m in re.finditer(r"(?:^|[\s(])id\s*==\s*([^)&\s]+)", s, re.IGNORECASE):
        _add_can(m.group(1))
    for m in re.finditer(r"busid\s*==\s*([^)&\s]+)", s, re.IGNORECASE):
        try:
            busids.add(int(m.group(1).strip().rstrip(")").strip(), 0))
        except ValueError:
            pass
    # fallback: bare 0x… literals if no can.id parsed
    if not can_ids:
        for hx in re.findall(r"0x[0-9A-Fa-f]+", s):
            try:
                can_ids.add(_normalize_hex_id(hx))
            except Exception:
                pass
    note = ""
    if can_ids or busids:
        parts = []
        if can_ids:
            parts.append(f"CAN id(s): {', '.join(sorted(can_ids))}")
        if busids:
            parts.append(f"busid(s): {', '.join(str(b) for b in sorted(busids))}")
        note = "; ".join(parts)
    return {"can_ids": can_ids, "busids": busids, "note": note}


def _filter_asc_paths_by_busid(asc_paths: list, busids: set):
    """
    Keep .asc files that match any busid: _DG{n}_ in name, n in basename, or file order index.
    If nothing matches, return original list and caller should record a warning.
    """
    if not busids or not asc_paths:
        return asc_paths, False
    matched = []
    for idx, path in enumerate(asc_paths):
        base = os.path.basename(path)
        ok = False
        for b in busids:
            if f"_DG{b}_" in base or f"_DG{b}." in base:
                ok = True
                break
            if str(b) in base:
                ok = True
                break
            if idx == b or idx + 1 == b:
                ok = True
                break
        if ok:
            matched.append(path)
    if matched:
        return matched, False
    return asc_paths, True


def _parse_asc_paths_from_stdout(stdout: str):
    paths = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s.startswith("->"):
            continue
        rest = s[2:].strip()
        if "(" in rest:
            rest = rest[: rest.rfind("(")].strip()
        if rest.endswith(".asc"):
            paths.append(rest)
    return paths


def _recent_asc_in_dir(output_dir: str, since_t: float):
    out = []
    try:
        for p in glob.glob(os.path.join(output_dir, "*.asc")):
            try:
                if os.path.getmtime(p) >= since_t - 0.5:
                    out.append(p)
            except OSError:
                pass
    except OSError:
        pass
    return out


def _looks_like_can_id_field(s: str) -> bool:
    s = s.strip()
    return bool(re.match(r"^0x[0-9A-Fa-f]+$", s))


def _looks_like_vector_can_error_id_field(id_field: str, line_lower: str) -> bool:
    """Vector ASC error rows use text in the ID column, or 'ErrorFrame' in the line."""
    t = id_field.strip().lower()
    if t in ("err", "error", "errorframe"):
        return True
    if t.startswith("error") and "frame" in t:
        return True
    if "errorframe" in line_lower.replace(" ", ""):
        return True
    return False


def _filter_asc_lines(path: str, can_ids: set, drop_flexray_null: bool) -> bool:
    """
    Filter CAN trace lines: if can_ids non-empty, keep only matching IDs.
    If can_ids empty, keep all CAN-form lines (still apply FlexRay-null drop if set).
    ErrorFrame-style lines are never dropped by ID filter. FlexRay-null only applies to rows
    with at least 6 tab columns (typical FlexRay export), not 4-column CAN (Timestamp/ID/DLC/Data).
    Returns True if file was modified.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return False
    if not lines:
        return False
    header_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("Timestamp") and "\t" in line:
            header_idx = i
            break
    out_lines = lines[: header_idx + 1]
    changed = False
    filter_by_id = bool(can_ids)
    for line in lines[header_idx + 1 :]:
        if not line.strip():
            out_lines.append(line)
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            out_lines.append(line)
            continue
        id_field = parts[1].strip()
        if _looks_like_vector_can_error_id_field(id_field, line.lower()):
            out_lines.append(line)
            continue
        if not _looks_like_can_id_field(id_field):
            out_lines.append(line)
            continue
        id_norm = _normalize_hex_id(id_field)
        if filter_by_id and id_norm not in can_ids:
            changed = True
            continue
        # FlexRay null-frame cleanup: only for wide rows (Vector FlexRay), not 4-col CAN tab (avoids stripping CAN errors DLC 0).
        if drop_flexray_null and len(parts) >= 6:
            data = parts[3].strip() if len(parts) > 3 else ""
            dlc = parts[2].strip() if len(parts) > 2 else "0"
            try:
                dlc_n = int(dlc, 0)
            except ValueError:
                dlc_n = -1
            if dlc_n == 0 and not data.replace(" ", ""):
                changed = True
                continue
        out_lines.append(line)
    if not changed:
        return False
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(out_lines)
    except OSError:
        return False
    return True


def _write_busmapping_sidecar(output_dir: str, input_basename: str, settings: dict) -> Optional[str]:
    """Write Type / Channel / Bus table for Vector tools. Returns path or None."""
    if not settings.get("write_busmapping"):
        return None
    buses = settings.get("buses") or []
    if not buses:
        return None
    path = os.path.join(output_dir, f"vector_asc_busmapping_{input_basename}.txt")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("Type\tChannel\tBus\n")
            for row in buses:
                f.write(f"{row.get('type', '')}\t{row.get('channel', '')}\t{row.get('bus', '')}\n")
        return path
    except OSError:
        return None


def _save_vector_settings_json(output_dir: str, input_basename: str, settings: dict):
    path = os.path.join(output_dir, f"vector_asc_settings_{input_basename}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
    except OSError:
        pass


def _run_vector_asc_postprocess(
    stdout: str,
    output_dir: str,
    input_basename: str,
    t0: float,
    settings: dict,
):
    """
    Apply busid file selection, CAN line filter, FlexRay-null, busmapping export; update JSON.
    """
    parsed = _parse_vector_filter_expression(settings.get("filter") or "")
    can_ids = parsed["can_ids"]
    busids = parsed["busids"]
    asc_paths = _parse_asc_paths_from_stdout(stdout or "")
    if not asc_paths:
        asc_paths = _recent_asc_in_dir(output_dir, t0)

    def _resolve_asc(p: str) -> Optional[str]:
        p = os.path.normpath(p.strip())
        if os.path.isfile(p):
            return os.path.abspath(p)
        base = os.path.basename(p)
        cand = os.path.join(output_dir, base)
        if os.path.isfile(cand):
            return os.path.abspath(cand)
        cand2 = os.path.join(output_dir, p)
        if os.path.isfile(cand2):
            return os.path.abspath(cand2)
        return None

    resolved_paths = []
    for p in asc_paths:
        r = _resolve_asc(p)
        if r:
            resolved_paths.append(r)
    if not resolved_paths:
        for p in _recent_asc_in_dir(output_dir, t0):
            r = _resolve_asc(p)
            if r:
                resolved_paths.append(r)
    asc_paths = resolved_paths

    busmapping_path = _write_busmapping_sidecar(output_dir, input_basename, settings)

    warn_busid = False
    if busids:
        asc_paths, warn_busid = _filter_asc_paths_by_busid(asc_paths, busids)

    flex_null = settings.get("filter_flexray_nullframes", False)
    any_change = False
    for ap in asc_paths:
        if _filter_asc_lines(ap, can_ids, flex_null):
            any_change = True

    extra = {
        "parsed_filter": {
            "can_ids": sorted(can_ids),
            "busids": sorted(busids),
            "note": parsed.get("note", ""),
        },
        "asc_files_processed": asc_paths,
        "busmapping_file": busmapping_path,
        "busid_fallback_all_files": warn_busid,
    }
    settings.update({"postprocess": extra})
    _save_vector_settings_json(output_dir, input_basename, settings)
    return extra


class VectorAscPanel(tk.Frame):
    """Vector ASC: filter, bus table, options; settings applied after MDF→ASCII conversion."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG_LIGHT_GRAY, **kwargs)
        self.write_busmapping_var = tk.BooleanVar(value=True)
        self.filter_flexray_var = tk.BooleanVar(value=False)
        self.bus_rows = []
        self._build()

    def _build(self):
        # Filter
        f = tk.Frame(self, bg=BG_LIGHT_GRAY)
        f.pack(fill=tk.X, pady=(0, 8))
        tk.Label(f, text="Filter:", bg=BG_LIGHT_GRAY, fg=TEXT_DARK, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        self.filter_entry = tk.Entry(
            f,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            bg=BG_WHITE,
            highlightthickness=1,
            highlightbackground=BORDER_GRAY,
        )
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=4)
        self.filter_entry.insert(0, FILTER_PLACEHOLDER)
        self.filter_entry.config(fg="gray")
        self.filter_entry.bind("<FocusIn>", self._on_filter_in)
        self.filter_entry.bind("<FocusOut>", self._on_filter_out)

        # Tabs
        tab_frame = tk.Frame(self, bg=BG_LIGHT_GRAY)
        tab_frame.pack(fill=tk.X, pady=(0, 8))
        self.tab_settings = tk.Frame(tab_frame, bg=BG_LIGHT_GRAY)
        self.tab_settings.pack(side=tk.LEFT, padx=(0, 16))
        tk.Label(self.tab_settings, text="Settings", font=("Segoe UI", 10), fg=ORANGE, bg=BG_LIGHT_GRAY, cursor="hand2").pack()
        tk.Frame(self.tab_settings, height=2, bg=ORANGE).pack(fill=tk.X, pady=(2, 0))
        tk.Label(tab_frame, text="Parameter View", font=("Segoe UI", 10), fg=TEXT_DARK, bg=BG_LIGHT_GRAY, cursor="hand2").pack(side=tk.LEFT)

        # Bus table
        table_frame = tk.Frame(self, bg=BG_WHITE, highlightthickness=1, highlightbackground=BORDER_GRAY)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        h = tk.Frame(table_frame, bg=BG_WHITE)
        h.pack(fill=tk.X)
        for col in ["Type", "Channel", "Bus"]:
            tk.Label(h, text=col, font=("Segoe UI", 9, "bold"), bg=BG_WHITE, fg=TEXT_DARK).pack(side=tk.LEFT, padx=8, pady=6)
        tk.Label(h, text="", width=2, bg=BG_WHITE).pack(side=tk.RIGHT, padx=4)
        tk.Frame(table_frame, height=1, bg=BORDER_GRAY).pack(fill=tk.X)

        self.rows_frame = tk.Frame(table_frame, bg=BG_WHITE)
        self.rows_frame.pack(fill=tk.BOTH, expand=True)
        self._add_bus_row()

        footer = tk.Frame(table_frame, bg=BG_WHITE)
        footer.pack(fill=tk.X, pady=8)
        tk.Button(footer, text="+", font=("", 12, "bold"), bg="#333", fg="white", relief=tk.FLAT, width=3, cursor="hand2", command=self._add_bus_row).pack(side=tk.LEFT, padx=8)
        tk.Label(footer, text="📤", font=("", 12), cursor="hand2").pack(side=tk.RIGHT, padx=4)
        tk.Label(footer, text="📥", font=("", 12), cursor="hand2").pack(side=tk.RIGHT, padx=4)

        cb_frame = tk.Frame(self, bg=BG_LIGHT_GRAY)
        cb_frame.pack(fill=tk.X)
        tk.Checkbutton(
            cb_frame,
            text="Write Busmapping",
            variable=self.write_busmapping_var,
            bg=BG_LIGHT_GRAY,
            activebackground=BG_LIGHT_GRAY,
            selectcolor=ORANGE,
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=(0, 20))
        tk.Checkbutton(
            cb_frame,
            text="Filter FlexRay-NullFrames (wide rows only)",
            variable=self.filter_flexray_var,
            bg=BG_LIGHT_GRAY,
            activebackground=BG_LIGHT_GRAY,
            selectcolor=ORANGE,
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT)

    def _on_filter_in(self, e):
        if self.filter_entry.get() == FILTER_PLACEHOLDER:
            self.filter_entry.delete(0, tk.END)
            self.filter_entry.config(fg=TEXT_DARK)

    def _on_filter_out(self, e):
        if not self.filter_entry.get().strip():
            self.filter_entry.insert(0, FILTER_PLACEHOLDER)
            self.filter_entry.config(fg="gray")

    def _add_bus_row(self):
        row = tk.Frame(self.rows_frame, bg=BG_WHITE)
        row.pack(fill=tk.X, pady=2)
        type_var = tk.StringVar(value="CAN")
        ch_var = tk.StringVar(value="1")
        bus_var = tk.StringVar(value="K_CAN_P")
        self.bus_rows.append((row, type_var, ch_var, bus_var))
        type_wrap = tk.Frame(row, bg=BLUE_HIGHLIGHT)
        type_wrap.pack(side=tk.LEFT, padx=8, pady=4)
        tcb = ttk.Combobox(type_wrap, textvariable=type_var, values=["CAN", "LIN", "FlexRay", "Ethernet"], width=9, state="readonly")
        tcb.pack(padx=2, pady=2)
        tk.Entry(row, textvariable=ch_var, width=6, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8, pady=4)
        ttk.Combobox(row, textvariable=bus_var, values=["K_CAN_P", "K_CAN_C", "K_LIN", "K_FlexRay"], width=12, state="readonly").pack(side=tk.LEFT, padx=8, pady=4)

        def remove_row():
            if len(self.bus_rows) <= 1:
                return
            self.bus_rows[:] = [x for x in self.bus_rows if x[0] != row]
            row.destroy()

        trash = tk.Label(row, text="🗑", font=("", 10), cursor="hand2", bg=BG_WHITE)
        trash.pack(side=tk.RIGHT, padx=8)
        trash.bind("<Button-1>", lambda e: remove_row())

    def export_settings(self):
        """Snapshot for JSON and post-processing."""
        ft = self.filter_entry.get().strip()
        if ft == FILTER_PLACEHOLDER:
            ft = ""
        buses = []
        for _row, tvar, chvar, busvar in self.bus_rows:
            buses.append(
                {"type": tvar.get(), "channel": chvar.get(), "bus": busvar.get()}
            )
        return {
            "filter": ft,
            "write_busmapping": self.write_busmapping_var.get(),
            "filter_flexray_nullframes": self.filter_flexray_var.get(),
            "buses": buses,
        }


class WriterBlock(tk.Frame):
    """Output format: simple row, or Vector ASC with extended panel."""
    def __init__(self, parent, format_label, vector_extended=False, **kwargs):
        super().__init__(parent, bg=BG_WHITE, **kwargs)
        self.format_label = format_label
        self.checked_var = tk.BooleanVar(value=True)
        self.vector_extended = vector_extended
        self.expanded_var = tk.BooleanVar(value=True)
        self.detail_frame = None
        self.vector_panel = None
        self._build()

    def _build(self):
        row = tk.Frame(self, bg=BG_WHITE)
        row.pack(fill=tk.X, pady=6)
        cb = tk.Checkbutton(row, variable=self.checked_var, bg=BG_WHITE, activebackground=BG_WHITE, selectcolor=ORANGE)
        cb.pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(row, text="all buses →", font=("Segoe UI", 10), bg=BG_WHITE, fg=TEXT_DARK).pack(side=tk.LEFT, padx=(0, 4))
        tk.Label(
            row,
            text=self.format_label,
            font=("Segoe UI", 10),
            bg=BG_WHITE,
            fg=TEXT_DARK,
            wraplength=280,
            justify=tk.LEFT,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, anchor=tk.W)

        if self.vector_extended:
            self.expand_lbl = tk.Label(row, text="▼", font=("Segoe UI", 10), bg=BG_WHITE, fg=TEXT_DARK, cursor="hand2")
            self.expand_lbl.pack(side=tk.LEFT, padx=4)
            self.expand_lbl.bind("<Button-1>", lambda e: self._toggle_expand())
            tk.Label(row, text="🗑", font=("", 10), cursor="hand2").pack(side=tk.RIGHT, padx=4)

        if self.vector_extended:
            self.detail_frame = tk.Frame(self, bg=BG_WHITE)
            self.detail_frame.pack(fill=tk.X, pady=(0, 8))
            self.vector_panel = VectorAscPanel(self.detail_frame, padx=4, pady=8)
            self.vector_panel.pack(fill=tk.BOTH, expand=True)

    def _toggle_expand(self):
        self.expanded_var.set(not self.expanded_var.get())
        if self.expanded_var.get():
            self.detail_frame.pack(fill=tk.X, pady=(0, 8))
            self.expand_lbl.config(text="▼")
        else:
            self.detail_frame.pack_forget()
            self.expand_lbl.config(text="▶")

    def get_format_config(self):
        return self.format_label

    def is_checked(self):
        return self.checked_var.get()

    def get_vector_settings(self):
        if self.vector_extended and hasattr(self, "vector_panel"):
            return self.vector_panel.export_settings()
        return None


class ConverterGUI:
    def __init__(self):
        self.exe_path = find_exe()
        self.root = tk.Tk()
        self.root.title("Start Conversion")
        self.root.minsize(640, 480)
        self.root.geometry("950x650")
        self.root.configure(bg=BG_WHITE)

        self.input_files = []
        self.writer_blocks = []
        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self.root, bg=ORANGE, height=48)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="☰", font=("Segoe UI", 18), bg=ORANGE, fg="white", cursor="hand2").pack(side=tk.LEFT, padx=16, pady=6)
        tk.Label(header, text="Start Conversion", font=("Segoe UI", 14, "bold"), bg=ORANGE, fg="white").pack(side=tk.LEFT, pady=10)

        main = tk.Frame(self.root, bg=BG_WHITE, padx=0, pady=0)
        main.pack(fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(main, bg=BG_WHITE)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=12)
        self.convert_btn = tk.Button(
            btn_frame,
            text="Convert",
            font=("Segoe UI", 11),
            bg=ORANGE,
            fg="white",
            relief=tk.FLAT,
            padx=24,
            pady=8,
            cursor="hand2",
            command=self._convert,
        )
        self.convert_btn.pack(side=tk.LEFT)
        if not self.exe_path:
            tk.Label(btn_frame, text="mdf2ascii.exe not found", fg="red", font=("Segoe UI", 9)).pack(side=tk.RIGHT)

        paned = tk.PanedWindow(main, orient=tk.HORIZONTAL, bg=BORDER_GRAY, sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: scrollable Input
        input_outer = tk.Frame(paned, bg=BG_WHITE)
        paned.add(input_outer, minsize=220)
        tk.Label(input_outer, text="Input", font=("Segoe UI", 12, "bold"), bg=BG_WHITE, fg=TEXT_DARK).pack(anchor=tk.W, padx=12, pady=(12, 8))
        scroll_in_outer, scroll_in = make_scrollable(input_outer, BG_WHITE)
        scroll_in_outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 12))

        add_btn = tk.Button(scroll_in, text="📄  Add files", font=("Segoe UI", 10), fg=TEXT_DARK, bg=BG_WHITE, relief=tk.FLAT, cursor="hand2", command=self._add_files)
        add_btn.pack(anchor=tk.W, pady=(0, 8))
        tk.Frame(scroll_in, height=1, bg=BORDER_GRAY).pack(fill=tk.X, pady=(0, 12))
        self.input_list_frame = tk.Frame(scroll_in, bg=BG_WHITE)
        self.input_list_frame.pack(fill=tk.X)

        # Right: scrollable Output
        output_outer = tk.Frame(paned, bg=BG_WHITE)
        paned.add(output_outer, minsize=280)
        tk.Label(output_outer, text="Output", font=("Segoe UI", 12, "bold"), bg=BG_WHITE, fg=TEXT_DARK).pack(anchor=tk.W, padx=12, pady=(12, 8))
        scroll_out_outer, scroll_out = make_scrollable(output_outer, BG_WHITE)
        scroll_out_outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 12))

        path_frame = tk.Frame(scroll_out, bg=BG_WHITE)
        path_frame.pack(fill=tk.X, pady=(0, 12))
        tk.Label(path_frame, text="📁", font=("", 14)).pack(side=tk.LEFT, padx=(0, 8))
        self.output_dir_var = tk.StringVar(value=DEFAULT_OUTPUT_DIR.replace("\\", "/"))
        path_entry = tk.Entry(path_frame, textvariable=self.output_dir_var, font=("Segoe UI", 10), relief=tk.FLAT, bg=BG_LIGHT_GRAY)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, ipady=6)
        browse_lbl = tk.Label(path_frame, text="📁", font=("", 14), cursor="hand2")
        browse_lbl.pack(side=tk.LEFT)
        browse_lbl.bind("<Button-1>", lambda e: self._browse_output_dir())

        tk.Label(scroll_out, text="Output formats", font=("Segoe UI", 9), fg="#666", bg=BG_WHITE).pack(anchor=tk.W, pady=(0, 4))
        tk.Label(
            scroll_out,
            text="Vector ASC: filter can.id / id / busid; bus file selection and line filter run after export. JSON + optional busmapping sidecar.",
            font=("Segoe UI", 8),
            fg="#888",
            bg=BG_WHITE,
            wraplength=400,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 6))

        self.writers_frame = tk.Frame(scroll_out, bg=BG_WHITE)
        self.writers_frame.pack(fill=tk.X, pady=(0, 8))

        for fmt in ["PCAP format", "Vector ASC"]:
            wb = WriterBlock(self.writers_frame, fmt, vector_extended=(fmt == "Vector ASC"))
            wb.pack(fill=tk.X, pady=(0, 8))
            self.writer_blocks.append(wb)

    def _add_files(self):
        paths = filedialog.askopenfilenames(filetypes=[("Supported", "*.mf4 *.mdf *.pcap *.pcapng *.asc"), ("All", "*.*")])
        for path in paths:
            if path and path not in [p for p, _ in self.input_files]:
                var = tk.BooleanVar(value=True)
                self.input_files.append((path, var))
                self._render_input_row(path, var)

    def _render_input_row(self, path, var):
        row = tk.Frame(self.input_list_frame, bg=BG_WHITE)
        row.pack(fill=tk.X, pady=4)
        cb = tk.Checkbutton(row, variable=var, bg=BG_WHITE, activebackground=BG_WHITE, selectcolor=ORANGE)
        cb.pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(row, text="▶", font=("Segoe UI", 10), bg=BG_WHITE, fg=TEXT_DARK).pack(side=tk.LEFT, padx=(0, 4))
        tk.Label(
            row,
            text=os.path.basename(path),
            font=("Segoe UI", 10),
            bg=BG_WHITE,
            fg=TEXT_DARK,
            wraplength=320,
            justify=tk.LEFT,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, anchor=tk.W)
        trash_lbl = tk.Label(row, text="🗑", font=("", 12), cursor="hand2")
        trash_lbl.pack(side=tk.RIGHT, padx=4)
        trash_lbl.bind("<Button-1>", lambda e, p=path: self._remove_input(p))

    def _remove_input(self, path):
        self.input_files[:] = [(p, v) for p, v in self.input_files if p != path]
        for w in self.input_list_frame.winfo_children():
            w.destroy()
        for path, var in self.input_files:
            self._render_input_row(path, var)

    def _browse_output_dir(self):
        path = filedialog.askdirectory(initialdir=self.output_dir_var.get())
        if path:
            self.output_dir_var.set(path.replace("\\", "/"))

    def _convert(self):
        if not self.exe_path:
            messagebox.showerror("Error", "mdf2ascii.exe not found.")
            return
        selected = [(p, v) for p, v in self.input_files if v.get() and os.path.isfile(p)]
        if not selected:
            messagebox.showerror("Error", "Select at least one input file.")
            return
        checked_writers = [w for w in self.writer_blocks if w.is_checked()]
        if not checked_writers:
            messagebox.showerror("Error", "Select at least one output format.")
            return

        output_dir = self.output_dir_var.get().strip().replace("/", "\\") or DEFAULT_OUTPUT_DIR
        os.makedirs(output_dir, exist_ok=True)
        env = os.environ.copy()
        env["CONVERTER_OUTPUT_DIR"] = os.path.abspath(output_dir)

        self.convert_btn.config(state=tk.DISABLED)
        self.root.update()
        ok_count = err_count = 0
        out_abs = os.path.abspath(output_dir)

        try:
            for input_path, _ in selected:
                in_ext = get_input_ext(input_path)
                base_name = os.path.splitext(os.path.basename(input_path))[0]
                for wb in checked_writers:
                    fmt = wb.get_format_config()
                    cfg = get_writer_config(fmt, in_ext)
                    if not cfg:
                        continue
                    args, _out_ext = cfg
                    cmd = [self.exe_path] + args + [input_path]
                    t0 = time.time()
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(self.exe_path), env=env)
                        if r.returncode != 0:
                            err_count += 1
                            continue
                        ok_count += 1
                        if fmt == "Vector ASC":
                            settings = wb.get_vector_settings() or {}
                            _run_vector_asc_postprocess(
                                r.stdout or "",
                                out_abs,
                                base_name,
                                t0,
                                settings,
                            )
                    except Exception:
                        err_count += 1

            if err_count == 0:
                messagebox.showinfo("Success", f"Conversion completed. {ok_count} conversion(s) done.")
            else:
                messagebox.showwarning("Partial", f"{ok_count} ok, {err_count} failed.")
        finally:
            self.convert_btn.config(state=tk.NORMAL)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ConverterGUI()
    app.run()
