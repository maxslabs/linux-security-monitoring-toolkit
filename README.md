# SSH Detect & Protect

A lightweight Linux SSH brute-force detection and monitoring tool built for SOC practice and cybersecurity learning.

## Overview
This tool analyzes SSH authentication logs using journalctl, extracts failed login attempts, and generates structured reports.

## Features
- SSH failed login detection from system logs
- Attacker IP extraction and grouping
- Target username analysis
- Severity classification (LOW / MEDIUM / HIGH)
- Filters localhost noise (::1)
- JSON report generation
- Human-readable log reports
- Attack simulation mode for safe testing
- Interactive CLI menu system

## How it works
1. Reads system SSH logs via journalctl
2. Filters 'Failed password' events
3. Extracts IP addresses and usernames using regex
4. Aggregates data using Python Counters
5. Generates structured reports

## Output
- Unique attackers
- Total failed attempts
- Top targeted usernames
- Severity per IP
- JSON + log files saved in /logs

## Project Structure
monitor.py
logs/
README.md
requirements.txt
diagram.dot

## Usage
sudo python3 monitor.py

## Security Note
This tool is designed for educational and lab environments only.
