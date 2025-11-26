# get_bypassed
A lightweight bash script that automates a set of common checks for sensitive file disclosure, path traversal, and some header-based bypasses

# Features
~ Checks for common sensitive files (e.g. .env, wp-config.php, .git/HEAD, backup files).
~ Attempts a variety of path traversal encodings and traversal techniques.
~ Tests parameter-based inclusion points using common parameter names.
~ Tests NULL-byte, Unicode-encoded, and header-based bypasses.
~ Outputs timestamped results to a user-specified file.
~ Minimal dependencies (bash + curl + standard core utilities).

# Requirements

~ Linux / macOS with bash (script uses bash features)
~ curl (required)
~ Common utilities: sed, tr, awk, sort, date (usually present on *nix systems)

# Usage
1. Make the script executable (only once):
chmod +x security_scanner.sh
2.  Run the script:
./get_bypassed.sh
3. Follow the prompts:
~ Enter the target URL (include protocol or let the script add https://).
~ Enter an output filename (default: security_test_results.txt).
~ Confirm to start.

# Output

~ The script writes human-readable log lines to the terminal and appends timestamped results to the output file you provide (default security_test_results.txt).
~ Summary printed on completion includes:
`Total tests executed
`Vulnerabilities found count
`Path to the results file

Important: The script marks potential findings conservatively (based on HTTP responses and content length). Always manually verify reported findings — false positives are possible.

# How it works (brief)

~ The script enumerates a list of common sensitive filenames and testing patterns.
~ It builds different URL variants using path traversal encodings and parameter injection.
~ For each test URL it performs an HTTP(S) request with curl, inspects the HTTP response code and content size, and logs any responses that look like they returned readable content for a private/config file.
~ Some bypass attempts include null-byte suffixes, unicode-encoded traversal, and IIS-specific headers (e.g., X-Original-URL).
