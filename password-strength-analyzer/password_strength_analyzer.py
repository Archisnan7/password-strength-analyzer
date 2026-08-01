"""
Password Strength Analyzer
---------------------------
A Tkinter desktop app that evaluates password strength in real time,
checks for reuse of personal info (name / date of birth), detects
common leaked passwords, sequential runs, and repeated characters,
estimates entropy, and suggests stronger alternatives using a
cryptographically secure RNG (Python's `secrets` module).

Run:
    python password_strength_analyzer.py
"""

import tkinter as tk
from tkinter import messagebox
import secrets
import string
import math
import re

# ---------------------------------------------------------------
# Color Theme Constants for Premium Dark Mode
# ---------------------------------------------------------------
BG_COLOR = "#0F172A"      # Deep dark slate background
CARD_BG = "#1E293B"       # Slightly lighter slate for card container
TEXT_COLOR = "#F8FAFC"    # High-contrast near white text
MUTED_TEXT = "#94A3B8"    # Medium gray for helper labels/subtitles
INPUT_BG = "#334155"      # Contrasting input field background
INPUT_FG = "#FFFFFF"      # White text inside inputs
ACCENT_BLUE = "#3B82F6"   # Premium blue for verification
ACCENT_GREEN = "#10B981"  # Emerald green for strong passwords
ACCENT_RED = "#EF4444"    # Rose red for weak passwords
ACCENT_ORANGE = "#F59E0B" # Amber orange for medium strength

# ------------------------------------------------------------------
# Common leaked / breached passwords (expanded curated list).
# Note: this is a static offline list for demo purposes. A production
# tool would check against a real breach dataset (e.g. HaveIBeenPwned's
# k-anonymity API) instead of a hardcoded list like this.
# ------------------------------------------------------------------
common_passwords = [
    "123456", "123456789", "password", "12345678", "qwerty", "123123", "111111", "12345", "1234567",
    "1234567890", "abc123", "password1", "1q2w3e4r", "iloveyou", "000000", "admin", "welcome", "monkey",
    "login", "letmein", "dragon", "master", "hello", "freedom", "whatever", "qazwsx", "trustno1", "654321",
    "superman", "football", "baseball", "shadow", "michael", "john", "sunshine", "princess", "starwars",
    "welcome123", "passw0rd", "password123", "1234", "12345678910", "qwertyuiop", "asdfghjkl",
    "1qaz2wsx", "zaq12wsx", "abcd1234", "changeme", "root", "toor",
]

# General weak patterns unrelated to personal info
weak_patterns = [
    "123", "abc", "password", "admin", "qwerty", "000", "111"
]

SEQUENTIAL_DIGITS = ["0123456789", "9876543210"]
SEQUENTIAL_LETTERS = ["abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba"]


# ------------------------------------------------------------------
# Helper: detect ascending/descending runs like "1234" or "dcba"
# ------------------------------------------------------------------
def has_sequential_run(password, min_run=4):
    lower = password.lower()
    for seq in SEQUENTIAL_DIGITS + SEQUENTIAL_LETTERS:
        for i in range(len(seq) - min_run + 1):
            if seq[i:i + min_run] in lower:
                return True
    return False


def has_repeated_chars(password, min_run=4):
    return bool(re.search(r"(.)\1{" + str(min_run - 1) + r",}", password))


# ------------------------------------------------------------------
# Helper: check password against user's name
# Splits the name using whitespace and punctuation marks (hyphens,
# apostrophes, etc.) to detect reuse of name components.
# ------------------------------------------------------------------
def name_reuse_found(password, name):
    if not name.strip():
        return []
    lower_pw = password.lower()
    hits = []

    # Split name by whitespace, standard punctuation, or curly quotes
    split_pattern = r"[\s" + re.escape(string.punctuation) + r"’“”‘]+"
    for token in re.split(split_pattern, name.strip().lower()):
        if len(token) >= 3 and token in lower_pw:
            hits.append(token)
    return hits


# ------------------------------------------------------------------
# Helper: check password against date of birth
# Accepts DOB in almost any format (DD-MM-YYYY, DD/MM/YYYY, YYYY-MM-DD, etc.)
# and also supports unseparated dates (DDMMYYYY).
# Checks common reuse patterns: full year, 2-digit year, DDMM, MMDD, etc.
# ------------------------------------------------------------------
def dob_reuse_found(password, dob):
    dob_lower = dob.strip().lower()
    if not dob_lower:
        return []
    digits = re.sub(r"\D", "", dob_lower)
    if len(digits) < 4:
        return []

    candidates = set()
    lower_pw = password.lower()

    # Try to parse parts split by common separators
    parts = re.split(r"[\/\-\. ]", dob_lower)
    parts = [p for p in parts if p]

    # Handle unseparated date of birth of 8 digits (DDMMYYYY)
    if len(parts) == 1 and len(digits) == 8:
        day = digits[0:2]
        month = digits[2:4]
        year = digits[4:8]
        parts = [day, month, year]

    if len(parts) == 3:
        p1, p2, p3 = parts
        # Normalize possible orders: DD MM YYYY or YYYY MM DD
        if len(p1) == 4:
            year, month, day = p1, p2, p3
        else:
            day, month, year = p1, p2, p3
        day = day.zfill(2)
        month = month.zfill(2)
        year = year.zfill(4) if len(year) == 4 else year
        candidates.update([
            year, year[-2:], day + month, month + day,
            day + month + year, month + day + year,
            year + month + day, day + month + year[-2:],
            month + day + year[-2:],
        ])
    else:
        # Fallback: just use raw digit blocks (e.g. only a year or 6 digits was given)
        candidates.update([digits, digits[-2:], digits[:4]])

    hits = [c for c in candidates if len(c) >= 2 and c in lower_pw]
    return sorted(set(hits), key=len, reverse=True)


# ------------------------------------------------------------------
# Helper: normalize leetspeak substitutions to standard characters
# to detect obfuscated weak patterns (e.g. P@ssw0rd -> password).
# ------------------------------------------------------------------
def normalize_leetspeak(text):
    leet_map = {
        '@': 'a', '4': 'a', '0': 'o', '1': 'i', '!': 'i', '3': 'e', '5': 's', '$': 's', '7': 't', '8': 'b', '9': 'g'
    }
    normalized = []
    for char in text:
        normalized.append(leet_map.get(char, char))
    return "".join(normalized)


# ------------------------------------------------------------------
# Shared scoring logic, used by both the checker and the suggestion
# generator so "Strong" means the exact same thing in both places.
# ------------------------------------------------------------------
def evaluate_password(password, name="", dob=""):
    # Enforce minimum length of 8 characters for further evaluation
    if len(password) < 8:
        return 0, "Weak", ["Password must be at least 8 characters. Please enter a longer password."]

    score = 0
    reasons = []

    # Length (guaranteed >= 8 at this point, but kept for scoring weight)
    if len(password) >= 8:
        score += 1

    # Uppercase
    if any(c.isupper() for c in password):
        score += 1
    else:
        reasons.append("Add uppercase letters.")

    # Lowercase
    if any(c.islower() for c in password):
        score += 1
    else:
        reasons.append("Add lowercase letters.")

    # Digits
    if any(c.isdigit() for c in password):
        score += 1
    else:
        reasons.append("Add numbers.")

    # Special characters
    if any(c in string.punctuation for c in password):
        score += 1
    else:
        reasons.append("Add special characters.")

    # Generic weak patterns (checks original lowercase and leetspeak-normalized strings)
    lower = password.lower()
    normalized = normalize_leetspeak(lower)
    detected_weak = set()
    for pattern in weak_patterns:
        if pattern in lower or pattern in normalized:
            detected_weak.add(pattern)

    for pattern in detected_weak:
        score -= 1
        reasons.append(f"Weak pattern detected: '{pattern}'")

    # Sequential runs
    if has_sequential_run(password):
        score -= 1
        reasons.append("Contains a sequential run (e.g. 1234, abcd).")

    # Repeated characters
    if has_repeated_chars(password):
        score -= 1
        reasons.append("Contains a repeated character run (e.g. aaaa).")

    # Name reuse
    name_hits = name_reuse_found(password, name)
    if name_hits:
        score -= 2
        reasons.append(f"Contains part of your name: {', '.join(name_hits)}")

    # DOB reuse
    dob_hits = dob_reuse_found(password, dob)
    if dob_hits:
        score -= 2
        reasons.append(f"Contains part of your date of birth: {', '.join(dob_hits)}")

    # Common / leaked password
    if lower in common_passwords:
        score = 0
        reasons.append("This password is commonly leaked!")

    score = max(score, 0)

    if score <= 2:
        strength = "Weak"
    elif score in (3, 4):
        strength = "Medium"
    else:
        strength = "Strong"

    return score, strength, reasons


# ------------------------------------------------------------------
# Remove every weak substring we can detect (generic weak patterns,
# name reuse, DOB reuse, sequential runs, repeated-char runs) so the
# suggestion isn't just "padded" but actually stripped of the exact
# things that were dragging the score down.
# ------------------------------------------------------------------
def strip_weak_substrings(password, name="", dob=""):
    lower = password.lower()
    spans = []  # (start, end) index ranges to cut out, in the ORIGINAL string

    for pattern in weak_patterns:
        idx = lower.find(pattern)
        if idx != -1:
            spans.append((idx, idx + len(pattern)))

    for token in name_reuse_found(password, name):
        idx = lower.find(token)
        if idx != -1:
            spans.append((idx, idx + len(token)))

    for hit in dob_reuse_found(password, dob):
        idx = lower.find(hit)
        if idx != -1:
            spans.append((idx, idx + len(hit)))

    for seq in SEQUENTIAL_DIGITS + SEQUENTIAL_LETTERS:
        for i in range(len(seq) - 3):
            run = seq[i:i + 4]
            idx = lower.find(run)
            if idx != -1:
                spans.append((idx, idx + len(run)))

    repeat_match = re.search(r"(.)\1{3,}", password)
    if repeat_match:
        spans.append(repeat_match.span())

    if not spans:
        return password

    # merge overlapping spans, then cut them all out
    spans.sort()
    merged = [spans[0]]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))

    kept = []
    prev_end = 0
    for s, e in merged:
        kept.append(password[prev_end:s])
        prev_end = e
    kept.append(password[prev_end:])
    return "".join(kept)


# ------------------------------------------------------------------
# Suggest a stronger version of the SAME password using Python's
# cryptographically secure 'secrets' module instead of standard 'random'.
# ------------------------------------------------------------------
def suggest_stronger_version(password, name="", dob=""):
    if not password:
        return ""

    cleaned = strip_weak_substrings(password, name, dob)
    if len(cleaned) < 4:
        # too much was stripped out to build on - keep a couple of the
        # user's original characters just to stay recognisable (up to 2 chars
        # so we don't accidentally keep a full weak pattern like "123" or "1234")
        cleaned = (cleaned + password)[:2]

    result = list(cleaned)

    if not any(c.isupper() for c in result):
        placed = False
        for i, c in enumerate(result):
            if c.isalpha():
                result[i] = c.upper()
                placed = True
                break
        if not placed:
            result.insert(0, secrets.choice(string.ascii_uppercase))

    if not any(c.islower() for c in result):
        result.append(secrets.choice(string.ascii_lowercase))

    if not any(c.isdigit() for c in result):
        result.append(secrets.choice(string.digits))

    if not any(c in string.punctuation for c in result):
        result.append(secrets.choice("!@#$%^&*"))

    # pad to 12+ chars - comfortably clears the length check and pushes
    # entropy well above the Weak/Medium threshold
    while len(result) < 12:
        result.append(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*"))

    candidate = "".join(result)

    # safety net: verify it actually scores Strong; if not (edge case),
    # top it up with more secure characters until it does
    guard = 0
    while evaluate_password(candidate, name, dob)[1] != "Strong" and guard < 10:
        candidate += secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*")
        guard += 1

    return candidate


# ---------------------------------------------------------------
# Suggest 2 to 3 distinct stronger alternatives
# ---------------------------------------------------------------
def suggest_stronger_versions(password, name="", dob="", count=3):
    suggestions = set()
    guard = 0
    # Keep generating until we hit count or safety threshold
    while len(suggestions) < count and guard < 20:
        sug = suggest_stronger_version(password, name, dob)
        if sug:
            suggestions.add(sug)
        guard += 1
    return sorted(list(suggestions))


# ---------------------------------------------------------------
# Canvas Strength Meter Updater
# ---------------------------------------------------------------
def update_strength_meter(strength):
    try:
        canvas.delete("all")
        bar_width = 80
        bar_height = 8
        spacing = 10

        # Color values corresponding to empty, Weak, Medium, and Strong
        colors = {
            "empty": ["#374151", "#374151", "#374151"],  # Dark gray
            "Weak": [ACCENT_RED, "#374151", "#374151"],
            "Medium": [ACCENT_ORANGE, ACCENT_ORANGE, "#374151"],
            "Strong": [ACCENT_GREEN, ACCENT_GREEN, ACCENT_GREEN]
        }

        active_colors = colors.get(strength, colors["empty"])

        for i in range(3):
            x0 = i * (bar_width + spacing)
            y0 = 0
            x1 = x0 + bar_width
            y1 = bar_height
            canvas.create_rectangle(
                x0, y0, x1, y1,
                fill=active_colors[i],
                outline="",
                width=0
            )
    except NameError:
        pass


# ---------------------------------------------------------------
# Real-time Password Strength check
# ---------------------------------------------------------------
def check_password(*args):
    try:
        password = password_var.get()
        name = name_var.get()
        dob = dob_var.get()
    except NameError:
        return

    if password == "":
        try:
            result.config(text="Strength : None | Entropy : 0 bits", fg=MUTED_TEXT)
            update_strength_meter("empty")
            suggestion.delete("1.0", tk.END)
            suggestion.insert(tk.END, "Enter a password to begin analysis...")
        except NameError:
            pass
        return

    score, strength, reasons = evaluate_password(password, name, dob)
    color = {"Weak": ACCENT_RED, "Medium": ACCENT_ORANGE, "Strong": ACCENT_GREEN}[strength]

    # Update visual bars
    update_strength_meter(strength)

    # Entropy calculation
    # Practical Entropy: Scaled by score/5.0 to reflect real-world weaknesses
    practical_entropy = 0
    if len(password) >= 8:
        charset = 0
        if any(c.islower() for c in password):
            charset += 26
        if any(c.isupper() for c in password):
            charset += 26
        if any(c.isdigit() for c in password):
            charset += 10
        if any(c in string.punctuation for c in password):
            charset += 32

        ideal_entropy = len(password) * math.log2(charset) if charset else 0
        # Practical adjustment: If the password contains weak patterns/reuse,
        # scale down the ideal entropy accordingly (score/5.0).
        practical_entropy = round(ideal_entropy * (score / 5.0), 2)

    try:
        result.config(
            text=f"Strength : {strength} | Entropy : {practical_entropy} bits",
            fg=color
        )
        suggestion.delete("1.0", tk.END)
        if reasons:
            suggestion.insert(tk.END, "Suggestions:\n\n")
            for r in reasons:
                suggestion.insert(tk.END, " • " + r + "\n")

            # Only provide strong replacement suggestions if length constraint is cleared
            if len(password) >= 8:
                suggestion.insert(tk.END, "\nTry one of these stronger alternatives:\n")
                alternatives = suggest_stronger_versions(password, name, dob, count=3)
                for alt in alternatives:
                    suggestion.insert(tk.END, f" • {alt}\n")
        else:
            suggestion.insert(tk.END, "Excellent Password! This password clears all basic checks.")
    except NameError:
        pass


# ------------------------------------------------------------------
# Cryptographically Secure Password generator (unrelated to user's input)
# ------------------------------------------------------------------
def generate_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(characters) for _ in range(12))
    try:
        password_var.set(password)
        show_var.set(True)
        entry.config(show="")
        toggle_btn.config(text="✕")  # Mask is removed, show cross symbol to hide it
    except NameError:
        pass


# ---------------------------------------------------------------
# Show / hide toggle
# ---------------------------------------------------------------
def toggle_password():
    try:
        if show_var.get():
            entry.config(show="")
            toggle_btn.config(text="✕")  # Password is visible, show cross to hide
        else:
            entry.config(show="*")
            toggle_btn.config(text="👁")  # Password is stars, show eye to view
    except NameError:
        pass


# -------------------------------------------------------------------
# Copy password to clipboard with visual feedback
# -------------------------------------------------------------------
def copy_to_clipboard():
    try:
        password = password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Nothing to copy!")
            return
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()

        # Micro-interaction: Change button text temporarily
        copy_btn.config(text="Copied!", bg=ACCENT_GREEN)
        root.after(1500, lambda: copy_btn.config(text="📋 Copy", bg=CARD_BG))
    except NameError:
        pass


# ---------------------------------------------------------------
# Clear all form entries
# ---------------------------------------------------------------
def clear_fields():
    try:
        password_var.set("")
        name_var.set("")
        dob_var.set("")
        show_var.set(False)
        entry.config(show="*")
        toggle_btn.config(text="👁")
    except NameError:
        pass


# ---------------------------------------------------------------
# GUI Setup
# ---------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Password Strength Analyzer")
    root.geometry("580x720")
    root.configure(bg=BG_COLOR)

    # StringVars for real-time validation traces
    password_var = tk.StringVar()
    name_var = tk.StringVar()
    dob_var = tk.StringVar()
    show_var = tk.BooleanVar(value=False)

    # Attach traces for live evaluations
    password_var.trace_add("write", lambda *args: check_password())
    name_var.trace_add("write", lambda *args: check_password())
    dob_var.trace_add("write", lambda *args: check_password())

    # Styling helper: Hover animations
    def on_enter(e, hover_bg):
        e.widget.config(bg=hover_bg)

    def on_leave(e, normal_bg):
        e.widget.config(bg=normal_bg)

    # Title Card
    title_frame = tk.Frame(root, bg=BG_COLOR)
    title_frame.pack(pady=(25, 10))
    title = tk.Label(
        title_frame, text="Password Strength Analyzer",
        font=("Segoe UI", 20, "bold"), fg=TEXT_COLOR, bg=BG_COLOR
    )
    title.pack()

    subtitle = tk.Label(
        title_frame, text="Analyze entropy, detect leaks, and generate highly secure keys.",
        font=("Segoe UI", 10), fg=MUTED_TEXT, bg=BG_COLOR
    )
    subtitle.pack(pady=(4, 0))

    # Main Card Container
    card = tk.Frame(root, bg=CARD_BG, padx=25, pady=25, highlightthickness=1,
                     highlightbackground="#334155")
    card.pack(pady=10, padx=30, fill=tk.BOTH, expand=True)

    # Row 1: Optional Personal Info (Name & DOB grid)
    personal_frame = tk.Frame(card, bg=CARD_BG)
    personal_frame.pack(fill=tk.X, pady=(0, 15))

    # Name Entry
    name_label = tk.Label(personal_frame, text="Your Name (optional)", font=("Segoe UI", 9, "bold"),
                           fg=MUTED_TEXT, bg=CARD_BG)
    name_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 4), padx=(0, 10))

    name_frame = tk.Frame(personal_frame, bg=INPUT_BG, padx=8, pady=6)
    name_frame.grid(row=1, column=0, sticky=tk.EW, padx=(0, 10))
    name_entry = tk.Entry(name_frame, textvariable=name_var, font=("Segoe UI", 11), fg=INPUT_FG,
                           bg=INPUT_BG, bd=0, highlightthickness=0, insertbackground="white")
    name_entry.pack(fill=tk.X)

    # DOB Entry
    dob_label = tk.Label(personal_frame, text="Date of Birth (optional)", font=("Segoe UI", 9, "bold"),
                          fg=MUTED_TEXT, bg=CARD_BG)
    dob_label.grid(row=0, column=1, sticky=tk.W, pady=(0, 4))

    dob_frame = tk.Frame(personal_frame, bg=INPUT_BG, padx=8, pady=6)
    dob_frame.grid(row=1, column=1, sticky=tk.EW)
    dob_entry = tk.Entry(dob_frame, textvariable=dob_var, font=("Segoe UI", 11), fg=INPUT_FG, bg=INPUT_BG,
                          bd=0, highlightthickness=0, insertbackground="white")
    dob_entry.pack(fill=tk.X)

    personal_frame.columnconfigure(0, weight=1)
    personal_frame.columnconfigure(1, weight=1)

    # Row 2: Password Input Label
    pass_label = tk.Label(card, text="Enter Password", font=("Segoe UI", 10, "bold"), fg=TEXT_COLOR,
                           bg=CARD_BG)
    pass_label.pack(anchor=tk.W, pady=(5, 4))

    # Custom padded Frame for Entry
    entry_frame = tk.Frame(card, bg=INPUT_BG, padx=8, pady=6)
    entry_frame.pack(fill=tk.X, pady=(0, 10))
    entry = tk.Entry(entry_frame, textvariable=password_var, font=("Segoe UI", 13), fg=INPUT_FG,
                      bg=INPUT_BG, show="*", bd=0, highlightthickness=0, insertbackground="white")
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # Visibility Toggle Button (Symbol)
    # Starts masked ("*"), so button shows eye ("👁") to reveal
    toggle_btn = tk.Button(
        entry_frame, text="👁", font=("Segoe UI", 11), fg=TEXT_COLOR, bg=INPUT_BG,
        activebackground=INPUT_BG, activeforeground=TEXT_COLOR, relief="flat", bd=0, cursor="hand2",
        command=lambda: [show_var.set(not show_var.get()), toggle_password()]
    )
    toggle_btn.pack(side=tk.LEFT, padx=(5, 5))

    # Copy Button
    copy_btn = tk.Button(
        entry_frame, text="📋 Copy", font=("Segoe UI", 9, "bold"), fg=TEXT_COLOR, bg=CARD_BG,
        activebackground=INPUT_BG, activeforeground=TEXT_COLOR, relief="flat", bd=0, cursor="hand2",
        padx=8,
        command=copy_to_clipboard
    )
    copy_btn.pack(side=tk.LEFT)
    copy_btn.bind("<Enter>", lambda e: on_enter(e, "#334155"))
    copy_btn.bind("<Leave>", lambda e: on_leave(e, CARD_BG))

    # Strength Meter Canvas Bar
    meter_frame = tk.Frame(card, bg=CARD_BG)
    meter_frame.pack(fill=tk.X, pady=(5, 10))
    canvas = tk.Canvas(meter_frame, width=260, height=8, bg=CARD_BG, bd=0, highlightthickness=0)
    canvas.pack(side=tk.LEFT)
    update_strength_meter("empty")

    # Strength Result / Entropy Label
    result = tk.Label(card, text="Strength : None | Entropy : 0 bits", font=("Segoe UI", 11, "bold"),
                       fg=MUTED_TEXT, bg=CARD_BG)
    result.pack(anchor=tk.W, pady=(0, 10))

    # Row 3: Action Buttons (Generate Key & Clear Fields)
    btn_frame = tk.Frame(card, bg=CARD_BG)
    btn_frame.pack(fill=tk.X, pady=5)
    generate_btn = tk.Button(
        btn_frame, text="Generate Key", font=("Segoe UI", 11, "bold"),
        bg=ACCENT_GREEN, fg="white", activebackground="#059669", relief="flat", bd=0, cursor="hand2",
        pady=8,
        command=generate_password
    )
    generate_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
    generate_btn.bind("<Enter>", lambda e: on_enter(e, "#059669"))
    generate_btn.bind("<Leave>", lambda e: on_leave(e, ACCENT_GREEN))

    clear_btn = tk.Button(
        btn_frame, text="Clear Fields", font=("Segoe UI", 11, "bold"),
        bg=INPUT_BG, fg=TEXT_COLOR, activebackground="#475569", relief="flat", bd=0, cursor="hand2",
        pady=8,
        command=clear_fields
    )
    clear_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))
    clear_btn.bind("<Enter>", lambda e: on_enter(e, "#475569"))
    clear_btn.bind("<Leave>", lambda e: on_leave(e, INPUT_BG))

    # Row 4: Suggestions Box
    suggestion_label = tk.Label(card, text="Analysis & Suggestions", font=("Segoe UI", 9, "bold"),
                                 fg=MUTED_TEXT, bg=CARD_BG)
    suggestion_label.pack(anchor=tk.W, pady=(15, 4))

    suggestion = tk.Text(card, font=("Segoe UI", 10), bg=INPUT_BG, fg=TEXT_COLOR, bd=0, highlightthickness=0,
                          insertbackground="white", wrap=tk.WORD, height=8)
    suggestion.pack(fill=tk.BOTH, expand=True)

    # Initialize analysis with empty check state
    check_password()

    root.mainloop()
