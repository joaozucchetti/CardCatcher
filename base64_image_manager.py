import base64
import hashlib
import mimetypes
import os
import re
import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageTk

    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

DATA_URL_RE = re.compile(
    r"data:((?:image|audio|font)\/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\r\n]+)",
    re.DOTALL,
)

MIME_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "image/bmp": ".bmp",
    "image/x-icon": ".ico",
    "font/woff": ".woff",
    "font/woff2": ".woff2",
    "font/ttf": ".ttf",
    "font/otf": ".otf",
    "font/eot": ".eot",
    "audio/mpeg": ".mp3",
    "audio/mp3": ".mp3",
    "audio/wav": ".wav",
    "audio/wave": ".wav",
    "audio/webm": ".webm",
    "audio/ogg": ".ogg",
    "audio/aac": ".m4a",
    "audio/m4a": ".m4a",
}


@dataclass
class DataUrlEntry:
    file_path: Path
    start: int
    end: int
    mime: str
    b64_data: str
    byte_size: int
    line: int
    col: int


def workspace_root() -> Path:
    return Path(__file__).resolve().parent


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def line_col_from_offset(text: str, offset: int) -> tuple[int, int]:
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)
    line = 1
    for i, start in enumerate(line_starts):
        if start > offset:
            line = i
            break
    else:
        line = len(line_starts)
    col = offset - line_starts[line - 1] + 1
    return line, col


def scan_file(path: Path) -> list[DataUrlEntry]:
    text = read_text(path)
    entries: list[DataUrlEntry] = []
    for match in DATA_URL_RE.finditer(text):
        mime = match.group(1)
        b64_data = match.group(2)
        b64_clean = "".join(b64_data.split())
        try:
            raw = base64.b64decode(b64_clean)
        except Exception:
            raw = b""
        line, col = line_col_from_offset(text, match.start())
        entries.append(
            DataUrlEntry(
                file_path=path,
                start=match.start(),
                end=match.end(),
                mime=mime,
                b64_data=b64_data,
                byte_size=len(raw),
                line=line,
                col=col,
            )
        )
    return entries


def list_html_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.html"))


def mime_to_ext(mime: str) -> str:
    return MIME_EXT.get(mime, mimetypes.guess_extension(mime) or ".bin")


def file_to_data_url(file_path: Path) -> tuple[str, str]:
    ext = file_path.suffix.lower()
    mime = mimetypes.types_map.get(ext, None)
    if not mime:
        if ext in [".jpg", ".jpeg"]:
            mime = "image/jpeg"
        elif ext == ".png":
            mime = "image/png"
        elif ext == ".webp":
            mime = "image/webp"
        elif ext == ".gif":
            mime = "image/gif"
        elif ext == ".svg":
            mime = "image/svg+xml"
        elif ext == ".bmp":
            mime = "image/bmp"
        elif ext == ".woff":
            mime = "font/woff"
        elif ext == ".woff2":
            mime = "font/woff2"
        elif ext == ".ttf":
            mime = "font/ttf"
        elif ext == ".otf":
            mime = "font/otf"
        elif ext == ".eot":
            mime = "application/vnd.ms-fontobject"
        elif ext == ".mp3":
            mime = "audio/mpeg"
        elif ext == ".wav":
            mime = "audio/wav"
        elif ext == ".ogg":
            mime = "audio/ogg"
        elif ext == ".webm":
            mime = "audio/webm"
        elif ext == ".m4a":
            mime = "audio/mp4"
        else:
            mime = "application/octet-stream"
    data = file_path.read_bytes()
    b64_data = base64.b64encode(data).decode("ascii")
    data_url = f"data:{mime};base64,{b64_data}"
    return mime, data_url


class Base64ImageManager(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Base64 Manager (Images, Fonts & Audio)")
        self.geometry("1200x720")

        self.entries: list[DataUrlEntry] = []
        self.filtered: list[DataUrlEntry] = []
        self.preview_image = None

        self._build_ui()
        self._refresh_preview(None)

    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=10, pady=8)

        ttk.Button(top, text="Scan HTML", command=self.scan_workspace).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(
            top, text="Extract + Replace", command=self.extract_and_replace
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Replace From File", command=self.replace_from_file).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(top, text="Delete Data URL", command=self.delete_data_url).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(top, text="Select Filtered", command=self.select_filtered).pack(
            side=tk.LEFT, padx=4
        )

        filter_row = ttk.Frame(self)
        filter_row.pack(fill=tk.X, padx=10, pady=4)

        ttk.Label(filter_row, text="MIME contains").pack(side=tk.LEFT)
        self.mime_filter = ttk.Entry(filter_row, width=20)
        self.mime_filter.pack(side=tk.LEFT, padx=6)

        ttk.Label(filter_row, text="Min KB").pack(side=tk.LEFT)
        self.min_kb = ttk.Entry(filter_row, width=8)
        self.min_kb.pack(side=tk.LEFT, padx=6)

        ttk.Label(filter_row, text="Max KB").pack(side=tk.LEFT)
        self.max_kb = ttk.Entry(filter_row, width=8)
        self.max_kb.pack(side=tk.LEFT, padx=6)

        ttk.Button(filter_row, text="Apply Filter", command=self.apply_filter).pack(
            side=tk.LEFT, padx=4
        )

        main = ttk.Frame(self)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.tree = ttk.Treeview(
            main,
            columns=("file", "mime", "size", "line"),
            show="headings",
            selectmode="extended",
        )
        self.tree.heading("file", text="File")
        self.tree.heading("mime", text="MIME")
        self.tree.heading("size", text="Size (KB)")
        self.tree.heading("line", text="Line")
        self.tree.column("file", width=360)
        self.tree.column("mime", width=160)
        self.tree.column("size", width=100, anchor=tk.E)
        self.tree.column("line", width=80, anchor=tk.E)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        preview = ttk.Frame(main)
        preview.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)

        self.preview_label = ttk.Label(preview, text="No selection")
        self.preview_label.pack(fill=tk.X)

        # Code context preview
        context_label = ttk.Label(preview, text="Code Context:")
        context_label.pack(fill=tk.X, pady=(8, 2))
        
        context_frame = ttk.Frame(preview)
        context_frame.pack(fill=tk.BOTH, expand=False)
        
        self.context_text = tk.Text(context_frame, height=6, wrap=tk.WORD, bg="#f5f5f5")
        context_scroll = ttk.Scrollbar(context_frame, command=self.context_text.yview)
        self.context_text.config(yscrollcommand=context_scroll.set)
        context_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.context_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.image_label = ttk.Label(preview)
        self.image_label.pack(fill=tk.BOTH, expand=True, pady=8)

        self.log = tk.Text(self, height=8)
        self.log.pack(fill=tk.BOTH, expand=False, padx=10, pady=6)

        if not PIL_AVAILABLE:
            self._log("Preview requires Pillow. Install with: pip install pillow")

    def _log(self, msg: str) -> None:
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def scan_workspace(self) -> None:
        root = workspace_root()
        html_files = list_html_files(root)
        self.entries = []
        for path in html_files:
            self.entries.extend(scan_file(path))
        self._log(f"Found {len(self.entries)} base64 URLs (images & fonts) in {len(html_files)} HTML files.")
        self.apply_filter()

    def apply_filter(self) -> None:
        mime_sub = self.mime_filter.get().strip().lower()
        min_kb = self._parse_float(self.min_kb.get())
        max_kb = self._parse_float(self.max_kb.get())

        def ok(entry: DataUrlEntry) -> bool:
            if mime_sub and mime_sub not in entry.mime.lower():
                return False
            size_kb = entry.byte_size / 1024.0
            if min_kb is not None and size_kb < min_kb:
                return False
            if max_kb is not None and size_kb > max_kb:
                return False
            return True

        self.filtered = [e for e in self.entries if ok(e)]
        self._refresh_tree()

    def _refresh_tree(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, entry in enumerate(self.filtered):
            rel = entry.file_path.relative_to(workspace_root())
            size_kb = entry.byte_size / 1024.0
            self.tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(str(rel), entry.mime, f"{size_kb:.1f}", entry.line),
            )

    def on_select(self, _event=None) -> None:
        items = self.tree.selection()
        if not items:
            self._refresh_preview(None)
            return
        entry = self.filtered[int(items[0])]
        self._refresh_preview(entry)

    def _refresh_preview(self, entry: DataUrlEntry | None) -> None:
        if entry is None:
            self.preview_label.config(text="No selection")
            self.image_label.config(image="", text="")
            self.preview_image = None
            return

        size_kb = entry.byte_size / 1024.0
        self.preview_label.config(
            text=f"{entry.mime} | {size_kb:.1f} KB | {entry.file_path.name}:{entry.line}"
        )

        # Handle audio files
        if entry.mime.startswith("audio/"):
            self.image_label.config(text=f"🔊 Audio file ({entry.mime})\nSize: {size_kb:.1f} KB")
            self.preview_image = None
            return

        # Handle font files
        if entry.mime.startswith("font/") or "font" in entry.mime.lower():
            self.image_label.config(text=f"🔤 Font file ({entry.mime})\nSize: {size_kb:.1f} KB")
            self.preview_image = None
            return

        if not PIL_AVAILABLE:
            self.image_label.config(text="Preview unavailable (Pillow missing).")
            self.preview_image = None
            return

        try:
            raw = base64.b64decode("".join(entry.b64_data.split()))
            image = Image.open(io_bytes(raw))
            image.thumbnail((480, 480))
            self.preview_image = ImageTk.PhotoImage(image)
            self.image_label.config(image=self.preview_image, text="")
        except Exception:
            self.image_label.config(text="Preview failed.")
            self.preview_image = None

    def select_filtered(self) -> None:
        self.tree.selection_remove(self.tree.selection())
        for idx in range(len(self.filtered)):
            self.tree.selection_add(str(idx))

    def _selected_entries(self) -> list[DataUrlEntry]:
        items = self.tree.selection()
        if not items:
            return []
        return [self.filtered[int(i)] for i in items]

    def extract_and_replace(self) -> None:
        selected = self._selected_entries()
        if not selected:
            messagebox.showinfo("No selection", "Select one or more items first.")
            return
        output_dir = workspace_root() / "assets" / "embedded"
        output_dir.mkdir(parents=True, exist_ok=True)

        replacements = {}
        for entry in selected:
            raw = base64.b64decode("".join(entry.b64_data.split()))
            digest = hashlib.sha1(raw).hexdigest()[:10]
            ext = mime_to_ext(entry.mime)
            file_name = f"embedded_{digest}{ext}"
            out_path = output_dir / file_name
            if not out_path.exists():
                out_path.write_bytes(raw)

            rel = os.path.relpath(out_path, entry.file_path.parent)
            rel = rel.replace("\\", "/")
            replacements.setdefault(entry.file_path, []).append((entry.start, entry.end, rel))

        self._apply_replacements(replacements)
        self.scan_workspace()
        self._log(f"Extracted and replaced {len(selected)} base64 items (images, fonts & audio).")

    def replace_from_file(self) -> None:
        selected = self._selected_entries()
        if not selected:
            messagebox.showinfo("No selection", "Select one or more items first.")
            return

        replacements = {}
        if len(selected) == 1:
            file_path = self._prompt_image_file("Select image, font, or audio file")
            if not file_path:
                return
            _, data_url = file_to_data_url(Path(file_path))
            entry = selected[0]
            replacements.setdefault(entry.file_path, []).append(
                (entry.start, entry.end, data_url)
            )
        else:
            use_same = messagebox.askyesno(
                "Replace multiple",
                "Replace all selected items with the same file?",
            )
            if use_same:
                file_path = self._prompt_image_file("Select image, font, or audio file for all")
                if not file_path:
                    return
                _, data_url = file_to_data_url(Path(file_path))
                for entry in selected:
                    replacements.setdefault(entry.file_path, []).append(
                        (entry.start, entry.end, data_url)
                    )
            else:
                for entry in selected:
                    title = (
                        f"Select file for {entry.file_path.name}:{entry.line}"
                    )
                    file_path = self._prompt_image_file(title)
                    if not file_path:
                        continue
                    _, data_url = file_to_data_url(Path(file_path))
                    replacements.setdefault(entry.file_path, []).append(
                        (entry.start, entry.end, data_url)
                    )

        self._apply_replacements(replacements)
        self.scan_workspace()
        self._log(f"Replaced {len(selected)} base64 items (images, fonts & audio).")

    def delete_data_url(self) -> None:
        selected = self._selected_entries()
        if not selected:
            messagebox.showinfo("No selection", "Select one or more items first.")
            return

        replacements = {}
        for entry in selected:
            replacements.setdefault(entry.file_path, []).append((entry.start, entry.end, ""))

        self._apply_replacements(replacements)
        self.scan_workspace()
        self._log(f"Deleted {len(selected)} base64 data URLs (images, fonts & audio).")

    def _apply_replacements(self, replacements: dict[Path, list[tuple[int, int, str]]]) -> None:
        for path, edits in replacements.items():
            text = read_text(path)
            for start, end, value in sorted(edits, key=lambda x: x[0], reverse=True):
                text = text[:start] + value + text[end:]
            path.write_text(text, encoding="utf-8")

    @staticmethod
    def _prompt_image_file(title: str) -> str:
        return filedialog.askopenfilename(
            title=title,
            filetypes=[
                ("Images, Fonts & Audio", "*.png;*.jpg;*.jpeg;*.webp;*.gif;*.svg;*.bmp;*.ico;*.woff;*.woff2;*.ttf;*.otf;*.eot;*.mp3;*.wav;*.ogg;*.webm;*.m4a"),
                ("Images", "*.png;*.jpg;*.jpeg;*.webp;*.gif;*.svg;*.bmp;*.ico"),
                ("Fonts", "*.woff;*.woff2;*.ttf;*.otf;*.eot"),
                ("Audio", "*.mp3;*.wav;*.ogg;*.webm;*.m4a"),
                ("All files", "*.*"),
            ],
        )

    @staticmethod
    def _parse_float(value: str) -> float | None:
        try:
            return float(value)
        except Exception:
            return None


def io_bytes(data: bytes):
    from io import BytesIO

    return BytesIO(data)


if __name__ == "__main__":
    app = Base64ImageManager()
    app.mainloop()
