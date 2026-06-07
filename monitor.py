import os
import re
import sys
import json
import subprocess
from datetime import datetime
from collections import Counter

# ======================
# CONFIG
# ======================
ALERT_THRESHOLD = 5
SAVE_REPORT = True
SIMULATE_ATTACK = False

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


# ======================
# PATCH NOTES
# ======================
def print_patch_notes():
    print("\n====================================================")
    print("Patch Notes (github.com/maxslabs)")
    print("====================================================")

    print("""
v1.3
- Added full menu-driven CLI system (SOC-style control panel)
- Added RUN mode for manual SSH log scanning
- Added SIMULATION mode for safe attack testing
- Separated execution flow (no automatic scanning on startup)
- Improved script structure for SOC tooling workflow

v1.2
- Added empty activity detection (no false reports)
- Improved severity classification logic
- Added JSON + human-readable report export
- Logs stored in /logs directory

v1.1
- Initial SSH log parser using journalctl
- IP extraction + username tracking
- Basic severity detection (LOW / MEDIUM / HIGH)
""")

# =====================
# INFO PANEL
# =====================
def print_info():
	print("\n===========================")
	print("SSH Detect & Protect - INFO")
	print("===========================\n")

	print("This tool monitors SSH failed login attempts.")
	print("It parses system logs using journalctl.")
	print("")
	print("It extracts:")
	print("- Attacker IP addresses")
	print("- Targeted usernames")
	print("- Number of failed attempts")

	print("\nIt then classifies severity:")
	print("- LOW: 1-3 attempts")
	print("- MEDIUM: 4-9 attempts")
	print("- HIGH: 10+ attempts (possible brute-force)")

	print("\nData sources:")
	print("- systemd journal (journalctl)")
	print("- SSH daemon logs (sshd)")
	print("============================\n")

# ======================
# MENU SYSTEM
# ======================
def menu():
    while True:
        print("\n====================")
        print("Controls")
        print("R - Run SSH Scan")
        print("I - Info")
        print("S - Simulate Attack")
        print("P - Patch Notes")
        print("Q - Quit")
        print("====================\n")

        choice = input("Enter choice: ").strip().lower()

        if choice == "r":
            return "run"

        if choice == "i":
            print_info()
            input("\nPress Enter to continue...")

        elif choice == "s":
            print("\n[+] Running attack simulation...\n")
            return "simulate"

        elif choice == "p":
            print_patch_notes()
            input("\nPress Enter to continue...")

        elif choice == "q":
            print("Exiting monitor...")
            sys.exit(0)

        else:
            print("Invalid option. Try again.")

    return True


# ======================
# SIMULATION (optional)
# ======================
def simulate_attack():
    return [
        "Failed password for invalid user fakeuser from 192.168.0.10",
        "Failed password for invalid user admin from 192.168.0.10",
        "Failed password for root from 192.168.0.10",
        "Failed password for invalid user test from 192.168.0.10",
        "Failed password for invalid user guest from 192.168.0.10",
    ]


# ======================
# SEVERITY ENGINE
# ======================
def get_severity(count):
    if count >= ALERT_THRESHOLD:
        return "HIGH"
    elif count >= 4:
        return "MEDIUM"
    elif count >= 1:
        return "LOW"
    return "NONE"


# ======================
# HEADER
# ======================
print("\n==============================")
print(" SSH Detect and Protect v1.3")
print(" - github.com/maxslabs -")
print("==============================")

mode = menu()


# ======================
# LOAD LOGS
# ======================
if mode == "simulate":
	lines = simulate_attack()

elif mode == "run":
    result = subprocess.run(
        ["journalctl", "--no-pager", "--since", "1 hour ago"],
        capture_output=True,
        text=True
    )
    lines = result.stdout.splitlines()

else:
        print("No valid mode selected.")
        sys.exit(0)

# ======================
# PARSING
# ======================
ip_counts = Counter()
user_counts = Counter()

for line in lines:
    if "Failed password" not in line:
        continue

    # IP extraction
    ip_match = re.search(r"from\s+([0-9a-fA-F\.:]+)", line)
    if ip_match:
        ip = ip_match.group(1)

        # remove localhost noise
        if ip != "::1":
            ip_counts[ip] += 1

    # username extraction
    user_match = re.search(r"Failed password for (?:invalid user )?(\w+)", line)
    if user_match:
        user_counts[user_match.group(1)] += 1


# ======================
# FILTERED DATA
# ======================
filtered_ips = dict(ip_counts)
total_failed = sum(filtered_ips.values())


# ======================
# OUTPUT
# ======================
print("\n==============================")
print(" RESULTS")
print("==============================\n")

if not filtered_ips:
    print("No suspicious SSH activity detected.")
else:
    for ip, count in filtered_ips.items():
        severity = get_severity(count)

        print(f"IP: {ip}")
        print(f"Attempts: {count}")
        print(f"Severity: {severity}")

        if severity == "HIGH":
            print("Status: Potential brute force attack!")

        print("-" * 30)


print("\n==============================")
print(f"Unique Attackers: {len(filtered_ips)}")
print(f"Total Failed SSH Attempts: {total_failed}")

print("\n=== Top Targeted Usernames ===\n")

for user, count in user_counts.most_common():
    print(f"{user}: {count}")


# ======================
# REPORTING
# ======================
if SAVE_REPORT and (filtered_ips or user_counts):

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    log_file = os.path.join(LOG_DIR, f"ssh_report_{timestamp}.log")
    json_file = os.path.join(LOG_DIR, f"ssh_report_{timestamp}.json")

    report = {
        "timestamp": str(datetime.now()),
        "attackers": filtered_ips,
        "usernames": dict(user_counts),
        "total_failed_attempts": total_failed,
        "unique_attackers": len(filtered_ips)
    }

    # JSON report
    with open(json_file, "w") as f:
        json.dump(report, f, indent=4)

    # Human readable report
    with open(log_file, "w") as f:
        f.write("SSH BRUTE FORCE INCIDENT REPORT\n")
        f.write("=" * 40 + "\n\n")

        f.write(f"Timestamp: {report['timestamp']}\n")
        f.write(f"Unique Attackers: {report['unique_attackers']}\n")
        f.write(f"Total Failed Attempts: {report['total_failed_attempts']}\n\n")

        f.write("Top Targeted Usernames:\n")
        for user, count in user_counts.most_common():
            f.write(f" - {user}: {count}\n")

        f.write("\nAttacker IPs:\n")
        for ip, count in filtered_ips.items():
            f.write(f" - {ip}: {count} attempts\n")

    print(f"\n[+] Human-readable report saved to: {log_file}")
    print(f"[+] JSON report saved to: {json_file}")
