import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# -----------------------
# Path / exclusion helpers
# -----------------------

def norm_win(path: str) -> str:
    """Normalize a path for Windows-style comparisons (case-insensitive)."""
    p = os.path.normcase(os.path.normpath(path))
    return p.rstrip("\\/")

def exclusion_relation(path: str, excluded_roots_norm: set) -> str | None:
    """
    Return:
      - "self"  if path is exactly an excluded root
      - "under" if path is inside (descendant of) an excluded root
      - None    otherwise
    """
    p = norm_win(path)
    for ex in excluded_roots_norm:
        if p == ex:
            return "self"
        if p.startswith(ex + os.sep):
            return "under"
    return None

# -----------------------
# Tree building
# -----------------------

def build_tree_lines(root: str, excluded_roots_norm: set) -> list[str]:
    """
    Build an ASCII tree of 'root'. If a directory is exactly excluded, show it
    as a stopping point (print its name but do not descend). Anything *under*
    an excluded root is not shown/descended.
    """
    if not os.path.isdir(root):
        return [f"[Not a directory] {root}"]

    lines: list[str] = []
    root_display = root  # keep original casing for display
    lines.append(root_display)

    # If the chosen root itself is excluded (exact match), show it and stop.
    if exclusion_relation(root, excluded_roots_norm) == "self":
        return lines

    def walk(dir_path: str, prefix: str):
        # Guard against descending into excluded subtrees
        if exclusion_relation(dir_path, excluded_roots_norm) == "under":
            return

        try:
            with os.scandir(dir_path) as it:
                entries = [e for e in it]
        except PermissionError:
            lines.append(prefix + "└── [Access Denied]")
            return
        except OSError as e:
            lines.append(prefix + f"└── [OS Error: {e.strerror or e}]")
            return

        # Sort: directories first, then files; both alphabetically
        dirs = sorted([e for e in entries if e.is_dir(follow_symlinks=False)], key=lambda e: e.name.lower())
        files = sorted([e for e in entries if e.is_file(follow_symlinks=False)], key=lambda e: e.name.lower())
        children = dirs + files

        for i, entry in enumerate(children):
            is_last = (i == len(children) - 1)
            branch = "└── " if is_last else "├── "
            next_prefix = prefix + ("    " if is_last else "│   ")
            full_path = os.path.join(dir_path, entry.name)

            rel = exclusion_relation(full_path, excluded_roots_norm)

            # Always show the entry name
            lines.append(prefix + branch + entry.name)

            if entry.is_dir(follow_symlinks=False):
                # If this folder is exactly excluded, print it but don't descend.
                if rel == "self":
                    continue
                # If it's under an excluded root, parent wouldn't descend anyway,
                # but keep the guard for safety.
                if rel == "under":
                    continue
                walk(full_path, next_prefix)
            else:
                # Files that are under an excluded root should not appear.
                if rel in ("self", "under"):
                    # A file equal to an excluded root is an edge case (unlikely),
                    # but we skip it for consistency.
                    continue

    walk(root, "")
    return lines

# -----------------------
# GUI
# -----------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Folder Tree (with Exclusions)")
        self.geometry("920x600")

        self.root_folder_var = tk.StringVar(value="")
        self.excluded_paths: list[str] = []          # display values (original casing)
        self.excluded_norm: set[str] = set()         # for fast comparisons (normalized)

        self._build_ui()

    def _build_ui(self):
        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)

        # Root selection row
        root_frame = ttk.Frame(outer)
        root_frame.pack(fill="x", pady=(0, 8))

        ttk.Label(root_frame, text="Root folder:").pack(side="left")
        self.root_entry = ttk.Entry(root_frame, textvariable=self.root_folder_var)
        self.root_entry.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(root_frame, text="Browse…", command=self.pick_root).pack(side="left")

        # Exclusions
        excl_frame = ttk.LabelFrame(outer, text="Excluded folders")
        excl_frame.pack(fill="both", pady=(0, 8))

        list_frame = ttk.Frame(excl_frame)
        list_frame.pack(fill="both", expand=True, padx=6, pady=6)

        self.excl_listbox = tk.Listbox(list_frame, height=6, selectmode=tk.EXTENDED)
        self.excl_listbox.pack(side="left", fill="both", expand=True)

        yscroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.excl_listbox.yview)
        yscroll.pack(side="left", fill="y")
        self.excl_listbox.config(yscrollcommand=yscroll.set)

        btns = ttk.Frame(excl_frame)
        btns.pack(fill="x", padx=6, pady=(0, 6))

        ttk.Button(btns, text="Add folder…", command=self.add_exclusion).pack(side="left")
        ttk.Button(btns, text="Remove selected", command=self.remove_selected_exclusions).pack(side="left", padx=(6, 0))

        # Submit
        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Submit", command=self.on_submit).pack(side="left")
        ttk.Button(actions, text="Clear Output", command=self.clear_output).pack(side="left", padx=(6, 0))

        # Output
        out_frame = ttk.LabelFrame(outer, text="Tree Output")
        out_frame.pack(fill="both", expand=True)

        self.output = tk.Text(out_frame, wrap="none")
        self.output.pack(side="left", fill="both", expand=True)

        out_scroll_y = ttk.Scrollbar(out_frame, orient="vertical", command=self.output.yview)
        out_scroll_y.pack(side="left", fill="y")
        self.output.config(yscrollcommand=out_scroll_y.set)

        out_scroll_x = ttk.Scrollbar(out_frame, orient="horizontal", command=self.output.xview)
        out_scroll_x.pack(side="bottom", fill="x")
        self.output.config(xscrollcommand=out_scroll_x.set, font=("Consolas", 10))

    # --------- UI callbacks ----------

    def pick_root(self):
        folder = filedialog.askdirectory(title="Select root folder")
        if folder:
            self.root_folder_var.set(folder)

    def add_exclusion(self):
        folder = filedialog.askdirectory(title="Select a folder to exclude")
        if not folder:
            return

        norm = norm_win(folder)
        # Avoid duplicates (normalize for equality)
        if norm in self.excluded_norm:
            messagebox.showinfo("Already excluded", "That folder is already in the exclusion list.")
            return

        # If the new exclusion is a parent/child of existing exclusions, keep only the most general one
        to_remove = []
        for existing_display in self.excluded_paths:
            ex_norm = norm_win(existing_display)
            # If the new one contains an existing one, remove the existing one
            if ex_norm.startswith(norm + os.sep) or ex_norm == norm:
                to_remove.append(existing_display)
            # If an existing one contains the new one, we can just refuse adding (already covered)
            elif norm.startswith(ex_norm + os.sep):
                messagebox.showinfo("Already covered",
                                    "A broader excluded folder already covers this path.")
                return

        for disp in to_remove:
            idxs = [i for i, v in enumerate(self.excluded_paths) if v == disp]
            for i in reversed(idxs):
                self.excl_listbox.delete(i)
                self.excluded_paths.pop(i)
            self.excluded_norm.discard(norm_win(disp))

        # Add the new exclusion
        self.excluded_paths.append(folder)
        self.excluded_norm.add(norm)
        self.excl_listbox.insert(tk.END, folder)

    def remove_selected_exclusions(self):
        # Remove in reverse index order so positions stay valid
        sel = list(self.excl_listbox.curselection())
        if not sel:
            return
        for i in reversed(sel):
            disp = self.excluded_paths.pop(i)
            self.excluded_norm.discard(norm_win(disp))
            self.excl_listbox.delete(i)

    def on_submit(self):
        root = self.root_folder_var.get().strip()
        if not root:
            messagebox.showwarning("No root", "Select a root folder first.")
            return
        if not os.path.isdir(root):
            messagebox.showerror("Invalid root", "Selected root is not a directory.")
            return

        self.output.config(state="normal")
        self.output.delete("1.0", tk.END)
        lines = build_tree_lines(root, self.excluded_norm)
        self.output.insert(tk.END, "\n".join(lines))
        self.output.config(state="normal")  # keep editable for easy copy/select

    def clear_output(self):
        self.output.config(state="normal")
        self.output.delete("1.0", tk.END)

if __name__ == "__main__":
    App().mainloop()
