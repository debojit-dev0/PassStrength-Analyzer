import argparse
import itertools
import math
import os
import string
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Set, Tuple

try:
    from zxcvbn import zxcvbn
except Exception:
    zxcvbn = None

try:
    import nltk
    from nltk.stem import WordNetLemmatizer
except Exception:
    nltk = None
    WordNetLemmatizer = None

@dataclass
class StrengthResult:
    password: str
    score: int
    crack_time_display: str
    feedback: str
    entropy_bits: float

LEET_MAP = {
    "a": ["4", "@"],
    "b": ["8"],
    "e": ["3"],
    "g": ["6", "9"],
    "i": ["1", "!"],
    "l": ["1", "|"] ,
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
    "z": ["2"],
}


def shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    freq = {ch: password.count(ch) for ch in set(password)}
    length = len(password)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return entropy * length


def analyze_password(password: str, user_inputs: Optional[Sequence[str]] = None) -> StrengthResult:
    user_inputs = list(user_inputs or [])
    entropy_bits = shannon_entropy(password)
    if zxcvbn:
        result = zxcvbn(password, user_inputs=user_inputs)
        score = result.get("score", 0)
        crack_time_display = result.get("crack_times_display", {}).get("offline_slow_hashing_1e4_per_second", "n/a")
        feedback_parts = result.get("feedback", {})
        warning = feedback_parts.get("warning") or ""
        suggestions = feedback_parts.get("suggestions") or []
        feedback = ". ".join([warning] + suggestions).strip(" .") or "No feedback"
    else:
        # Fallback heuristic if zxcvbn is missing
        char_space = len(set(password))
        naive_bits = math.log2(char_space or 1) * len(password)
        score = min(4, int(naive_bits // 20))
        crack_time_display = "zxcvbn not installed; using heuristic"
        feedback = "Install zxcvbn for richer analysis"
    return StrengthResult(password=password, score=score, crack_time_display=crack_time_display, feedback=feedback, entropy_bits=entropy_bits)


def ensure_nltk() -> Optional[WordNetLemmatizer]:
    if nltk is None or WordNetLemmatizer is None:
        return None
    try:
        nltk.data.find("corpora/wordnet")
    except LookupError:
        nltk.download("wordnet", quiet=True)
    return WordNetLemmatizer()


def tokenize_inputs(raw_inputs: Sequence[str]) -> List[str]:
    lemmatizer = ensure_nltk()
    tokens: List[str] = []
    for item in raw_inputs:
        for token in item.replace("_", " ").replace("-", " ").split():
            token = token.strip()
            if not token:
                continue
            tokens.append(token)
            if lemmatizer:
                try:
                    tokens.append(lemmatizer.lemmatize(token))
                except Exception:
                    pass
    return list(dict.fromkeys(tokens))


def case_variants(token: str) -> Set[str]:
    variants = {token.lower(), token.upper(), token.title()}
    if token and token[0].isalpha():
        variants.add(token[0].upper() + token[1:])
    return variants


def apply_leetspeak(token: str, max_variants: int = 128) -> Set[str]:
    chars = []
    for ch in token:
        options = [ch]
        if ch.lower() in LEET_MAP:
            options.extend(LEET_MAP[ch.lower()])
        chars.append(options)
    variants: Set[str] = set()
    for combo in itertools.product(*chars):
        variants.add("".join(combo))
        if len(variants) >= max_variants:
            break
    return variants


def append_years(tokens: Iterable[str], years: Sequence[int]) -> Set[str]:
    combos: Set[str] = set()
    for token in tokens:
        combos.add(token)
        for y in years:
            combos.add(f"{token}{y}")
            combos.add(f"{token}{str(y)[-2:]}")
    return combos


def add_separators(tokens: Iterable[str], separators: Sequence[str]) -> Set[str]:
    combos: Set[str] = set()
    tokens = list(tokens)
    for a, b in itertools.permutations(tokens, 2):
        for sep in separators:
            combos.add(f"{a}{sep}{b}")
    return combos


def build_wordlist(user_inputs: Sequence[str], years: Sequence[int], separators: Sequence[str], include_leet: bool, max_size: int = 50000) -> List[str]:
    base_tokens = tokenize_inputs(user_inputs)
    expanded: Set[str] = set()
    for token in base_tokens:
        expanded.update(case_variants(token))
        if include_leet:
            expanded.update(apply_leetspeak(token))
    expanded.update(add_separators(expanded, separators))
    expanded = append_years(expanded, years)
    wordlist = list(dict.fromkeys(expanded))
    if len(wordlist) > max_size:
        wordlist = wordlist[:max_size]
    return wordlist


def parse_years(years_arg: str) -> List[int]:
    years: List[int] = []
    for part in years_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            try:
                years.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                years.append(int(part))
            except ValueError:
                continue
    if not years:
        current_year = datetime.now().year
        years = [current_year - 1, current_year, current_year + 1]
    return sorted(set(y for y in years if 1900 <= y <= 2100))


def run_cli(args: argparse.Namespace) -> None:
    if args.password:
        result = analyze_password(args.password, user_inputs=args.inputs)
        print("Password Analysis")
        print("=" * 30)
        print(f"Score (0-4): {result.score}")
        print(f"Shannon entropy (bits): {result.entropy_bits:.2f}")
        print(f"Crack time (offline slow hash): {result.crack_time_display}")
        print(f"Feedback: {result.feedback}")
        print()
    if args.wordlist:
        years = parse_years(args.years)
        wordlist = build_wordlist(args.inputs, years=years, separators=args.separators, include_leet=not args.no_leet, max_size=args.max_size)
        os.makedirs(os.path.dirname(args.wordlist) or ".", exist_ok=True)
        with open(args.wordlist, "w", encoding="utf-8") as f:
            for item in wordlist:
                f.write(item + "\n")
        print(f"Generated wordlist with {len(wordlist)} entries -> {args.wordlist}")


def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog
    except Exception as exc:  # pragma: no cover - UI only
        print(f"Tkinter is not available: {exc}")
        return

    root = tk.Tk()
    root.title("Password Strength & Wordlist")
    root.geometry("520x520")

    # Frames
    pw_frame = ttk.LabelFrame(root, text="Password Analysis")
    pw_frame.pack(fill="x", padx=10, pady=10)

    ttk.Label(pw_frame, text="Password:").pack(anchor="w", padx=6, pady=4)
    pw_entry = ttk.Entry(pw_frame, show="*", width=50)
    pw_entry.pack(padx=6, pady=4, fill="x")

    feedback_var = tk.StringVar()
    ttk.Label(pw_frame, textvariable=feedback_var, wraplength=480).pack(anchor="w", padx=6, pady=4)

    def on_analyze():
        pwd = pw_entry.get()
        res = analyze_password(pwd)
        feedback_var.set(f"Score: {res.score} | Entropy: {res.entropy_bits:.2f} bits | Crack time: {res.crack_time_display}\n{res.feedback}")

    ttk.Button(pw_frame, text="Analyze", command=on_analyze).pack(padx=6, pady=4)

    # Wordlist frame
    wl_frame = ttk.LabelFrame(root, text="Custom Wordlist")
    wl_frame.pack(fill="both", expand=True, padx=10, pady=10)

    ttk.Label(wl_frame, text="Inputs (comma separated):").pack(anchor="w", padx=6, pady=4)
    inputs_entry = ttk.Entry(wl_frame, width=50)
    inputs_entry.pack(padx=6, pady=4, fill="x")

    ttk.Label(wl_frame, text="Years (e.g., 1990-1995,2024)").pack(anchor="w", padx=6, pady=4)
    years_entry = ttk.Entry(wl_frame, width=50)
    years_entry.insert(0, f"{datetime.now().year-1}-{datetime.now().year+1}")
    years_entry.pack(padx=6, pady=4, fill="x")

    include_leet_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(wl_frame, text="Include leetspeak variants", variable=include_leet_var).pack(anchor="w", padx=6, pady=4)

    size_var = tk.IntVar(value=50000)
    ttk.Label(wl_frame, text="Max entries").pack(anchor="w", padx=6, pady=2)
    size_scale = ttk.Scale(wl_frame, from_=1000, to=100000, orient="horizontal", variable=size_var)
    size_scale.pack(fill="x", padx=6, pady=2)

    status_var = tk.StringVar(value="Ready")
    ttk.Label(wl_frame, textvariable=status_var, wraplength=480).pack(anchor="w", padx=6, pady=6)

    def on_generate():
        raw_inputs = [i.strip() for i in inputs_entry.get().split(",") if i.strip()]
        years = parse_years(years_entry.get())
        wordlist = build_wordlist(raw_inputs, years=years, separators=["", "_", "-", ".", "!"], include_leet=include_leet_var.get(), max_size=size_var.get())
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], title="Save wordlist")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for item in wordlist:
                f.write(item + "\n")
        status_var.set(f"Saved {len(wordlist)} entries to {path}")
        messagebox.showinfo("Wordlist saved", f"Saved {len(wordlist)} entries to {path}")

    ttk.Button(wl_frame, text="Generate & Save", command=on_generate).pack(padx=6, pady=6)

    root.mainloop()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Password strength analyzer and custom wordlist generator")
    parser.add_argument("--password", help="Password to analyze")
    parser.add_argument("--inputs", nargs="*", default=[], help="Personal data inputs (name, pet, dates)")
    parser.add_argument("--years", default="", help="Years as range/list: 1990-1995,2024")
    parser.add_argument("--wordlist", default=None, help="Output path for generated wordlist (.txt)")
    parser.add_argument("--separators", nargs="*", default=["", "_", "-", "."], help="Separators between tokens")
    parser.add_argument("--no-leet", action="store_true", help="Disable leetspeak variants")
    parser.add_argument("--max-size", type=int, default=50000, help="Maximum number of wordlist entries")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter GUI")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = build_arg_parser().parse_args(argv)
    if args.gui:
        launch_gui()
        return
    if not args.password and not args.wordlist:
        print("Provide --password to analyze and/or --wordlist to generate a list. Use --gui for a GUI.")
        return
    run_cli(args)


if __name__ == "__main__":
    main()
