# Password Strength Analyzer & Custom Wordlist Generator

A Python CLI/GUI tool that scores password strength (zxcvbn fallback to heuristic) and produces focused attack wordlists from personal inputs, leetspeak patterns, separators, and year suffixes.

## Quick start

1. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
2. (Optional) Download NLTK data for lemmatization:
   ```bash
   python - <<'PY'
   import nltk
   nltk.download('wordnet')
   PY
   ```

## CLI usage

Analyze a password only:
```bash
python password_tool.py --password "S3cureP@ss!"
```

Generate a custom wordlist:
```bash
python password_tool.py --inputs alice fluffy 1996 --years 1990-1996,2024 --wordlist out.txt
```

Analyze and generate at once:
```bash
python password_tool.py --password "P@ssw0rd" --inputs john soccer 2010 --wordlist john.txt
```

Key flags:
- `--inputs`: space-separated personal terms (names, pets, hobbies, dates).
- `--years`: ranges/lists, e.g., `1990-1995,2024` (defaults to current year +/- 1).
- `--separators`: separators used when combining tokens (default: none, `_`, `-`, `.`).
- `--no-leet`: disable leetspeak variants.
- `--max-size`: cap wordlist entries (default 50k).
- `--gui`: open Tkinter GUI.

Output wordlists are plain `.txt` compatible with common cracking tools.

## GUI usage

Run:
```bash
python password_tool.py --gui
```
Enter a password to score and supply comma-separated inputs plus a year pattern to save a wordlist.

## Notes

- zxcvbn yields richer feedback; if absent, a heuristic score/entropy is used.
- Wordlists are deduplicated and truncated to `--max-size` to stay manageable.
