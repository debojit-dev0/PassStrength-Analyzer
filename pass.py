import argparse
from zxcvbn import zxcvbn
from itertools import product

# -------------------------------
# Password Strength Analyzer
# -------------------------------
def analyze_password(password):
    result = zxcvbn(password)

    print("\n🔐 Password Strength Analysis")
    print("-" * 30)
    print(f"Score (0–4): {result['score']}")
    print(f"Crack Time (offline fast hash): {result['crack_times_display']['offline_fast_hashing_1e10_per_second']}")
    
    if result['feedback']['warning']:
        print("⚠ Warning:", result['feedback']['warning'])
    
    for suggestion in result['feedback']['suggestions']:
        print("👉 Suggestion:", suggestion)


# -------------------------------
# Wordlist Generator
# -------------------------------
def leetspeak(word):
    replacements = {
        'a': ['a', '@', '4'],
        'e': ['e', '3'],
        'i': ['i', '1'],
        'o': ['o', '0'],
        's': ['s', '$', '5']
    }

    chars = []
    for c in word.lower():
        chars.append(replacements.get(c, [c]))

    return [''.join(p) for p in product(*chars)]


def generate_wordlist(inputs, years):
    wordlist = set()

    for word in inputs:
        word = word.strip()
        if not word:
            continue

        variants = set()
        variants.add(word)
        variants.add(word.lower())
        variants.add(word.capitalize())
        variants.add(word.upper())

        # Leetspeak variants
        for l in leetspeak(word):
            variants.add(l)

        # Append years & numbers
        for v in variants:
            wordlist.add(v)
            for y in years:
                wordlist.add(f"{v}{y}")
                wordlist.add(f"{y}{v}")
                wordlist.add(f"{v}@{y}")
                wordlist.add(f"{v}#{y}")

    return sorted(wordlist)


# -------------------------------
# Save Wordlist
# -------------------------------
def save_wordlist(wordlist, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for word in wordlist:
            f.write(word + "\n")
    print(f"\n✅ Wordlist saved as: {filename}")
    print(f"🔢 Total words generated: {len(wordlist)}")


# -------------------------------
# CLI Interface
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer & Custom Wordlist Generator")

    parser.add_argument("--password", help="Password to analyze")
    parser.add_argument("--inputs", nargs="+", help="Personal keywords (name, pet, city, etc.)")
    parser.add_argument("--years", nargs="+", default=["2022", "2023", "2024", "2025"], help="Years to append")
    parser.add_argument("--output", default="wordlist.txt", help="Output wordlist file")

    args = parser.parse_args()

    if args.password:
        analyze_password(args.password)

    if args.inputs:
        wordlist = generate_wordlist(args.inputs, args.years)
        save_wordlist(wordlist, args.output)

    if not args.password and not args.inputs:
        parser.print_help()


if __name__ == "__main__":
    main()
