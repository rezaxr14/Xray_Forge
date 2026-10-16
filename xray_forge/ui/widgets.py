"""
Custom Tkinter UI widgets: Tooltip, animated Switch toggle, etc.
"""

import tkinter as tk

MONO = "Courier"
SANS = "Helvetica"
BG = "#0e1117"
PURPLE = "#bc8cff"


class Tooltip:
    def __init__(self, widget: tk.Misc, text: str, delay: int = 450):
        self.w = widget
        self.t = text
        self.d = delay
        self._id: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._sched, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _sched(self, _event=None) -> None:
        if self._id:
            self.w.after_cancel(self._id)
        self._id = self.w.after(self.d, self._show)

    def _show(self) -> None:
        if self._tip:
            return
        x = self.w.winfo_rootx() + 14
        y = self.w.winfo_rooty() + self.w.winfo_height() + 6
        self._tip = tw = tk.Toplevel(self.w)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self.t, justify="left", background="#212836",
                 foreground="#dbe4ee", relief="solid", borderwidth=1,
                 font=(MONO, 9), padx=9, pady=6).pack()

    def _hide(self, _event=None) -> None:
        if self._id:
            self.w.after_cancel(self._id)
            self._id = None
        if self._tip:
            self._tip.destroy()
            self._tip = None


class Switch(tk.Canvas):
    """Animated iOS-style toggle bound to a BooleanVar."""

    def __init__(self, master: tk.Misc, variable: tk.BooleanVar,
                 command=None, w: int = 44, h: int = 22,
                 on_color: str = PURPLE, off_color: str = "#30363d"):
        super().__init__(master, width=w, height=h, bg=BG,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.var = variable
        self.command = command
        self.w_, self.h_ = w, h
        self.on_color, self.off_color = on_color, off_color
        self._anim_id: str | None = None
        self._t = 1.0 if variable.get() else 0.0
        r = h // 2
        self._rect = self.create_rectangle(r, 2, w - r, h - 2,
                                           fill=self._mix(), outline="")
        self._ov1 = self.create_oval(2, 2, 2 + 2 * r, h - 2,
                                     fill=self._mix(), outline="")
        self._ov2 = self.create_oval(w - 2 - 2 * r, 2, w - 2, h - 2,
                                     fill=self._mix(), outline="")
        self._knob_r = (h - 8) // 2
        kx = self._knob_x(self._t)
        self._knob = self.create_oval(
            kx - self._knob_r, h // 2 - self._knob_r,
            kx + self._knob_r, h // 2 + self._knob_r,
            fill="#e6edf3", outline="")
        self.bind("<Button-1>", self._toggle)
        variable.trace_add("write", lambda *_a: self._sync())

    def _knob_x(self, t: float) -> float:
        x0 = 4 + self._knob_r
        x1 = self.w_ - 4 - self._knob_r
        return x0 + (x1 - x0) * t

    def _mix(self) -> str:
        c1 = tuple(int(self.off_color[i:i + 2], 16) for i in (1, 3, 5))
        c2 = tuple(int(self.on_color[i:i + 2], 16) for i in (1, 3, 5))
        return "#%02x%02x%02x" % tuple(
            int(a + (b - a) * self._t) for a, b in zip(c1, c2))

    def _render(self) -> None:
        col = self._mix()
        for item in (self._rect, self._ov1, self._ov2):
            self.itemconfigure(item, fill=col)
        kx = self._knob_x(self._t)
        self.coords(self._knob, kx - self._knob_r, self.h_ // 2 - self._knob_r,
                    kx + self._knob_r, self.h_ // 2 + self._knob_r)

    def _sync(self) -> None:
        target = 1.0 if self.var.get() else 0.0
        if self._anim_id:
            self.after_cancel(self._anim_id)
            self._anim_id = None
        self._animate(target)

    def _animate(self, target: float) -> None:
        step = 0.28
        if abs(target - self._t) <= step:
            self._t = target
            self._render()
            self._anim_id = None
            return
        self._t += step if target > self._t else -step
        self._render()
        self._anim_id = self.after(16, lambda: self._animate(target))

    def _toggle(self, _e=None) -> None:
        self.var.set(not self.var.get())
        if self.command:
            self.command()
