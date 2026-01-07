## Password Security Agent - standalone script
## Save as password_security_agent.py
import math
import re
import time
import random
import string
import csv
from typing import List, Dict, Any, Optional

# Optional: pandas/matplotlib used only if available
try:
    import pandas as pd
    import matplotlib.pyplot as plt
except Exception:
    pd = None
    plt = None

DEFAULT_GUESSES_PER_SECOND = 1e9  # attacker speed (guesses/sec)
COMMON_PASSWORDS = {
    "123456","password","123456789","12345678","12345","qwerty","abc123","football",
    "111111","1234567","princess","admin","welcome","iloveyou","monkey"
}
KEYBOARD_SEQS = [
    "qwertyuiop","asdfghjkl","zxcvbnm",
    "1234567890","!@#$%^&*()"
]

# Utility functions
def detect_char_classes(pw: str):
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    return has_lower, has_upper, has_digit, has_symbol

def estimate_charset_size(pw: str):
    has_lower, has_upper, has_digit, has_symbol = detect_char_classes(pw)
    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digit:
        size += 10
    if has_symbol:
        size += 32
    if size == 0:
        size = 1
    return size

def entropy_bits(pw: str):
    L = len(pw)
    charset = estimate_charset_size(pw)
    if charset <= 1:
        return 0.0
    return L * math.log2(charset)

def crack_time_seconds(entropy_bits_value: float, guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND):
    try:
        combos = 2 ** entropy_bits_value
    except OverflowError:
        return float('inf')
    avg_guesses = combos / 2.0
    secs = avg_guesses / guesses_per_second
    return secs

def human_readable_time(seconds):
    if seconds is None:
        return "Unknown"
    if seconds == float('inf'):
        return "Centuries (practically uncrackable with current compute)"
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    intervals = [
        ('years', 3600*24*365),
        ('days', 3600*24),
        ('hours', 3600),
        ('minutes', 60),
        ('seconds', 1)
    ]
    parts = []
    remaining = int(seconds)
    for name, count in intervals:
        if remaining >= count:
            val = remaining // count
            remaining = remaining % count
            parts.append(f"{val} {name}")
    if not parts:
        return "0 seconds"
    return ", ".join(parts[:2])

# Heuristics & detectors
def contains_common_password(pw: str):
    pw_lower = pw.lower()
    for p in COMMON_PASSWORDS:
        if p == pw_lower:
            return True, p
    return False, None

def detect_sequences(pw: str):
    pw_lower = pw.lower()
    seq_found = []
    for i in range(len(pw_lower) - 3):
        segment = pw_lower[i:i+4]
        alph = "abcdefghijklmnopqrstuvwxyz"
        rev_alph = alph[::-1]
        nums = "0123456789"
        rev_nums = nums[::-1]
        for seq in (alph, rev_alph, nums, rev_nums):
            if segment in seq:
                seq_found.append(segment)
    for k in KEYBOARD_SEQS:
        for i in range(len(k) - 3):
            seg = k[i:i+4]
            if seg in pw_lower:
                seq_found.append(seg)
    return list(set(seq_found))

def detect_repeated_chars(pw: str):
    repeats = re.findall(r'(.)\1{3,}', pw)  # runs of 4+ same char
    return repeats

def detect_year_or_dob(pw: str):
    years = re.findall(r'19\d{2}|20\d{2}', pw)
    filtered = [y for y in years if 1900 <= int(y) <= 2099]
    return filtered

def dictionary_word_check(pw: str):
    words = re.findall(r'[A-Za-z]{4,}', pw)
    found = [w for w in words if w.lower() in COMMON_PASSWORDS]
    return found

# Scoring engine
def compute_score(pw: str, user_info: Optional[str]=None, guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND):
    reasons = []
    recs = []
    L = len(pw)
    entropy = entropy_bits(pw)
    secs = crack_time_seconds(entropy, guesses_per_second)

    # baseline mapping from entropy -> 0-100
    if entropy <= 0:
        base = 0
    elif entropy < 28:
        base = int((entropy / 28.0) * 30)
    elif entropy < 60:
        base = 30 + int(((entropy - 28) / (60-28)) * 40)
    elif entropy < 80:
        base = 70 + int(((entropy - 60) / (80-60)) * 20)
    else:
        base = 90 + min(10, int(((entropy - 80) / 48.0) * 10))
    base = max(0, min(100, base))

    penalty = 0

    is_common, which = contains_common_password(pw)
    if is_common:
        reasons.append(f"Exact match with very common password: '{which}'")
        penalty += 60

    seqs = detect_sequences(pw)
    if seqs:
        reasons.append(f"Contains sequential pattern(s): {', '.join(seqs)}")
        penalty += 20

    reps = detect_repeated_chars(pw)
    if reps:
        reasons.append(f"Contains repeated char runs: {', '.join(reps)}")
        penalty += 15

    years = detect_year_or_dob(pw)
    if years:
        reasons.append(f"Contains year-like numbers: {', '.join(years)}")
        penalty += 15

    dict_found = dictionary_word_check(pw)
    if dict_found:
        reasons.append(f"Contains common word(s): {', '.join(dict_found)}")
        penalty += 20

    if user_info:
        ui = user_info.lower()
        if ui and ui.strip():
            if ui in pw.lower() or any(part in pw.lower() for part in ui.split()):
                reasons.append("Password contains user-provided personal information")
                penalty += 30

    if L < 8:
        reasons.append("Password length is less than 8 characters (too short)")
        penalty += 20
    elif L < 12:
        reasons.append("Consider using 12+ characters for stronger security")
        penalty += 5

    score = base - penalty
    score = max(0, min(100, int(score)))

    if score >= 80:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    if score < 80:
        recs.append("Use a longer passphrase (12+ chars).")
        recs.append("Mix upper, lower, digits and symbols.")
    if seqs:
        recs.append("Avoid sequential patterns like 'abcd' or '1234'.")
    if reps:
        recs.append("Avoid repeated characters and long runs like 'aaaa'.")
    if years:
        recs.append("Avoid using years or DOB in password.")
    if is_common:
        recs.append("Do NOT use common passwords; choose a unique passphrase.")
    recs.append("Consider using a password manager to generate and store strong passwords.")

    return {
        "password": pw,
        "length": L,
        "entropy_bits": round(entropy, 2),
        "crack_time_seconds": secs,
        "crack_time_human": human_readable_time(secs),
        "score": score,
        "risk_level": risk,
        "reasons": reasons,
        "recommendations": recs
    }

# Pretty print helper
def analyze_and_print(pw: str, user_info: Optional[str]=None, guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND):
    result = compute_score(pw, user_info=user_info, guesses_per_second=guesses_per_second)
    print("=== Password Security Report ===")
    print(f"Password: {result['password']}")
    print(f"Length: {result['length']}")
    print(f"Entropy (bits): {result['entropy_bits']}")
    print(f"Estimated average crack time: {result['crack_time_human']}")
    print(f"Score (0-100): {result['score']}  Risk Level: {result['risk_level']}")
    if result['reasons']:
        print("\\nReasons:")
        for r in result['reasons']:
            print(" -", r)
    if result['recommendations']:
        print("\\nRecommendations:")
        for r in result['recommendations']:
            print(" -", r)
    return result

# Agent class
class PasswordSecurityAgent:
    def __init__(self,
                 guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND,
                 auto_save: bool = False,
                 save_path: str = "agent_reports.csv",
                 alert_threshold: int = 50):
        self.guesses_per_second = guesses_per_second
        self.auto_save = auto_save
        self.save_path = save_path
        self.alert_threshold = alert_threshold
        self.history: List[Dict[str, Any]] = []

    def analyze(self, password: str, user_info: Optional[str] = None) -> Dict[str,Any]:
        res = compute_score(password, user_info=user_info, guesses_per_second=self.guesses_per_second)
        res["_analyzed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        res["_source"] = "interactive"
        self.history.append(res)
        if self.auto_save:
            self._append_csv([res])
        self._check_triggers(res)
        return res

    def batch_analyze(self, passwords: List[str]) -> List[Dict[str,Any]]:
        results = []
        for pw in passwords:
            r = compute_score(pw, user_info=None, guesses_per_second=self.guesses_per_second)
            r["_analyzed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            r["_source"] = "batch"
            results.append(r)
            self.history.append(r)
        if self.auto_save:
            self._append_csv(results)
        for r in results:
            self._check_triggers(r)
        return results

    def enforce_policy(self, password: str, policy: Dict[str,Any]) -> Dict[str,Any]:
        reasons = []
        ok = True
        L = len(password)
        if policy.get("min_length") and L < policy["min_length"]:
            ok = False
            reasons.append(f"length<{policy['min_length']}")
        if policy.get("require_upper") and not any(c.isupper() for c in password):
            ok = False
            reasons.append("missing uppercase")
        if policy.get("require_lower") and not any(c.islower() for c in password):
            ok = False
            reasons.append("missing lowercase")
        if policy.get("require_digit") and not any(c.isdigit() for c in password):
            ok = False
            reasons.append("missing digit")
        if policy.get("require_symbol") and not any(not c.isalnum() for c in password):
            ok = False
            reasons.append("missing symbol")
        if policy.get("no_year"):
            years = detect_year_or_dob(password)
            if years:
                ok = False
                reasons.append("contains-year")
        return {"policy_ok": ok, "reasons": reasons}

    def generate_strong_password(self, length: int = 16, use_symbols: bool = True) -> str:
        if length < 8: length = 8
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        if use_symbols:
            chars += "!@#$%^&*()-_=+[]{}<>?/"
        pw = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits)
        ]
        if use_symbols:
            pw.append(random.choice("!@#$%^&*()-_=+[]{}<>?/"))
        while len(pw) < length:
            pw.append(random.choice(chars))
        random.shuffle(pw)
        return "".join(pw)

    def suggest_fix(self, password: str, user_info: Optional[str]=None) -> Dict[str,Any]:
        analysis = compute_score(password, user_info=user_info, guesses_per_second=self.guesses_per_second)
        suggestion = self.generate_strong_password(length=max(16, len(password)+4))
        rationale = []
        if analysis["score"] < 80:
            rationale.append("Password score below 80 — suggesting a stronger random password.")
        if analysis.get("reasons"):
            rationale.append("Issues detected: " + "; ".join(analysis.get("reasons",[]))[:200])
        rationale = rationale or ["Suggested a stronger password by default."]
        return {"analysis": analysis, "suggested_password": suggestion, "rationale": rationale}

    def _check_triggers(self, analysis_result: Dict[str,Any]):
        score = analysis_result.get("score", 100)
        if score <= self.alert_threshold:
            print("\\n!!! ALERT: Low-score password detected (score <= {}) !!!".format(self.alert_threshold))
            print(f"Password: {analysis_result['password']}  Score: {analysis_result['score']}  Risk: {analysis_result['risk_level']}")
            try:
                self._append_csv([analysis_result], append_to=f"critical_{self.save_path}")
            except Exception:
                pass

    def _append_csv(self, rows: List[Dict[str,Any]], append_to: Optional[str]=None):
        path = append_to or self.save_path
        keys = ["_analyzed_at","password","length","entropy_bits","crack_time_human","score","risk_level"]
        try:
            write_header = False
            try:
                with open(path, "r", encoding="utf-8") as f:
                    if f.read().strip() == "":
                        write_header = True
            except FileNotFoundError:
                write_header = True
            with open(path, "a", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                if write_header:
                    writer.writerow(keys)
                for r in rows:
                    writer.writerow([r.get(k,"") for k in keys])
        except Exception as e:
            print("Warning: failed to append CSV:", e)

    def show_history(self, limit: int = 20):
        for r in self.history[-limit:]:
            print(f"[{r.get('_analyzed_at')}] {r['password']} | Score: {r['score']} | Risk: {r['risk_level']}")

    def export_history_df(self):
        try:
            if pd:
                return pd.DataFrame(self.history)
        except Exception:
            pass
        return None

# Interactive menu
def run_interactive_menu():
    try:
        import getpass
    except Exception:
        getpass = None

    agent = PasswordSecurityAgent(auto_save=False, save_path="password_results.csv", alert_threshold=50)

    def print_menu():
        menu = """
Password Security Agent - Menu
1) Analyze a single password
2) Batch analyze multiple passwords (comma-separated or newline-separated)
3) Suggest a stronger password for an input
4) Save last results to CSV (if any)
5) Show analysis history (last 20)
6) Exit
"""
        print(menu)

    def analyze_single():
        if getpass:
            try:
                pw = getpass.getpass("Enter password to analyze (input hidden): ")
            except Exception:
                pw = input("Enter password to analyze: ").strip()
            if not pw:
                pw = input("No input received. Enter password (visible): ").strip()
        else:
            pw = input("Enter password to analyze: ").strip()
        if not pw:
            print("No password provided. Returning to menu.")
            return
        user_info = input("Optional - Enter related user-info (name/email) or press Enter to skip: ").strip()
        res = agent.analyze(pw, user_info=user_info if user_info else None)
        print("\\n=== Analysis Result ===")
        analyze_and_print(pw, user_info=user_info if user_info else None, guesses_per_second=agent.guesses_per_second)

    def analyze_batch():
        print("Enter passwords separated by commas or new lines. End input with an empty line.")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                break
            lines.append(line)
        raw = "\\n".join(lines).strip()
        if not raw:
            print("No input provided. Returning to menu.")
            return
        pw_list = []
        for part in raw.split(","):
            for sub in part.splitlines():
                if sub.strip():
                    pw_list.append(sub.strip())
        if not pw_list:
            print("No valid passwords parsed. Returning to menu.")
            return
        results = agent.batch_analyze(pw_list)
        if agent.export_history_df() is not None:
            df = agent.export_history_df()
            try:
                display(df[["password","length","entropy_bits","crack_time_human","score","risk_level"]].tail(len(results)))
            except Exception:
                print("Batch results:")
                for r in results:
                    print(f"{r['password']}  | Score: {r['score']}  | Risk: {r['risk_level']}  | Crack: {r['crack_time_human']}")
        else:
            print("\\nBatch results:")
            for r in results:
                print(f"{r['password']}  | Score: {r['score']}  | Risk: {r['risk_level']}  | Crack: {r['crack_time_human']}")

    def suggest_fix():
        if getpass:
            try:
                pw = getpass.getpass("Enter password to get suggestion for (input hidden): ")
            except Exception:
                pw = input("Enter password to analyze: ").strip()
            if not pw:
                pw = input("No input received. Enter password (visible): ").strip()
        else:
            pw = input("Enter password to get suggestion for: ").strip()
        if not pw:
            print("No password provided. Returning to menu.")
            return
        user_info = input("Optional - Enter related user-info (name/email) or press Enter to skip: ").strip()
        suggestion = agent.suggest_fix(pw, user_info=user_info if user_info else None)
        print("\\n=== Suggestion ===")
        print("Suggested password:", suggestion["suggested_password"])
        print("Rationale:", "; ".join(suggestion["rationale"]))
        print("\\nOriginal password analysis:")
        analyze_and_print(pw, user_info=user_info if user_info else None, guesses_per_second=agent.guesses_per_second)

    def save_csv():
        if not agent.history:
            print("No results are available to save. Run an analysis first.")
            return
        filename = input("Enter filename to save (default: password_results.csv): ").strip() or "password_results.csv"
        try:
            agent._append_csv(agent.history, append_to=filename)
            print(f"Saved {len(agent.history)} rows to {filename}")
        except Exception as e:
            print("Failed to save via agent:", e)

    def show_history():
        if not agent.history:
            print("History is empty.")
            return
        agent.show_history(limit=20)

    while True:
        print_menu()
        choice = input("Enter choice (1-6): ").strip()
        if choice == "1":
            analyze_single()
        elif choice == "2":
            analyze_batch()
        elif choice == "3":
            suggest_fix()
        elif choice == "4":
            save_csv()
        elif choice == "5":
            show_history()
        elif choice == "6":
            print("Exiting menu. Goodbye.")
            break
        else:
            print("Invalid choice. Please enter 1-6.")
        print("\\n" + "-"*60 + "\\n")

if __name__ == "__main__":
    run_interactive_menu()
