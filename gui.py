"""Tkinter desktop interface for IPA64-Converter."""

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.ipa_reader import IPAError, inspect_ipa


class IPA64App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("IPA64-Converter")
        self.root.geometry("760x560")
        self.root.minsize(620, 420)
        self.ipa_path = None
        self.report = None

        outer = ttk.Frame(root, padding=14)
        outer.pack(fill="both", expand=True)

        heading = ttk.Label(
            outer,
            text="IPA64-Converter",
            font=("Segoe UI", 18, "bold"),
        )
        heading.pack(anchor="w")

        subtitle = ttk.Label(
            outer,
            text="Анализ архитектуры и сведений iOS-приложений",
        )
        subtitle.pack(anchor="w", pady=(2, 12))

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 10))

        self.open_button = ttk.Button(
            controls, text="Открыть IPA…", command=self.open_ipa
        )
        self.open_button.pack(side="left")

        self.save_button = ttk.Button(
            controls, text="Сохранить отчёт…", command=self.save_report,
            state="disabled",
        )
        self.save_button.pack(side="left", padx=(8, 0))

        self.copy_button = ttk.Button(
            controls, text="Копировать JSON", command=self.copy_report,
            state="disabled",
        )
        self.copy_button.pack(side="left", padx=(8, 0))

        self.path_label = ttk.Label(
            outer, text="Файл не выбран", wraplength=700
        )
        self.path_label.pack(anchor="w", pady=(0, 8))

        self.output = tk.Text(
            outer,
            wrap="word",
            font=("Consolas", 10),
            height=18,
            state="disabled",
        )
        self.output.pack(fill="both", expand=True)

        footer = ttk.Label(
            outer,
            text="Анализатор не изменяет IPA и не выполняет его содержимое.",
            foreground="#666666",
        )
        footer.pack(anchor="w", pady=(9, 0))

    def show_text(self, value: str):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", value)
        self.output.configure(state="disabled")

    def open_ipa(self):
        path = filedialog.askopenfilename(
            title="Выберите iOS IPA",
            filetypes=[("iOS application", "*.ipa"), ("All files", "*.*")],
        )
        if not path:
            return

        self.ipa_path = path
        self.report = None
        self.path_label.configure(text=path)
        self.save_button.configure(state="disabled")
        self.copy_button.configure(state="disabled")
        self.show_text("Анализируем IPA…")
        self.root.update_idletasks()

        try:
            self.report = inspect_ipa(path)
        except IPAError as exc:
            self.show_text("")
            messagebox.showerror("Ошибка анализа", str(exc))
            return
        except Exception as exc:
            self.show_text("")
            messagebox.showerror(
                "Неожиданная ошибка",
                f"{type(exc).__name__}: {exc}",
            )
            return

        rendered = json.dumps(self.report, ensure_ascii=False, indent=2)
        self.show_text(rendered)
        self.save_button.configure(state="normal")
        self.copy_button.configure(state="normal")

    def copy_report(self):
        if self.report is None:
            return

        rendered = json.dumps(self.report, ensure_ascii=False, indent=2)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(rendered)
            self.root.update()
        except tk.TclError as exc:
            messagebox.showerror("Ошибка копирования", str(exc))
            return

        messagebox.showinfo("Скопировано", "JSON-отчёт скопирован в буфер обмена.")

    def save_report(self):
        if self.report is None:
            return

        destination = filedialog.asksaveasfilename(
            title="Сохранить JSON-отчёт",
            defaultextension=".json",
            initialfile="ipa-report.json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not destination:
            return

        try:
            with open(destination, "w", encoding="utf-8") as output_file:
                json.dump(
                    self.report,
                    output_file,
                    ensure_ascii=False,
                    indent=2,
                )
                output_file.write("\n")
        except OSError as exc:
            messagebox.showerror("Ошибка сохранения", str(exc))
            return

        messagebox.showinfo("Готово", f"Отчёт сохранён:\n{destination}")


def main():
    root = tk.Tk()
    IPA64App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
