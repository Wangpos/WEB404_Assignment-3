#!/usr/bin/env bash
# Automated attack/defence test suite for the file upload lab.
# Usage: start the server (npm start) in another terminal, then run: npm test
# Run `npm run reset` (and restart the server) before re-running, so the rate limiter starts fresh.

BASE="${BASE_URL:-http://localhost:3000}"
P="samples/payloads"
PASS=0
FAIL=0
TMP=$(mktemp)

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

if ! curl -s -o /dev/null "$BASE/"; then
  echo -e "${RED}Server is not running at $BASE. Start it with: npm start${NC}"
  exit 1
fi
[ -d "$P" ] || node samples/generate-samples.js > /dev/null

# upload <endpoint> <curl -F value> -> prints "<status> <body>"
upload() {
  curl -s -o "$TMP" -w '%{http_code}' -F "$2" "$BASE$1"
}

# check <description> <endpoint> <expected status> <curl -F value>
check() {
  local desc="$1" endpoint="$2" expected="$3" form="$4"
  local status body
  status=$(upload "$endpoint" "$form")
  body=$(head -c 160 "$TMP")
  if [ "$status" = "$expected" ]; then
    PASS=$((PASS + 1)); printf "${GREEN}[PASS]${NC} %-58s -> %s\n" "$desc" "$status"
  else
    FAIL=$((FAIL + 1)); printf "${RED}[FAIL]${NC} %-58s -> %s (expected %s)\n" "$desc" "$status" "$expected"
  fi
  echo "         $body"
}

echo -e "\n${YELLOW}=== PART A: Attacking the VULNERABLE endpoint (/vulnerable/upload) ===${NC}"
echo "Expected: malicious files are ACCEPTED (200) - this shows the vulnerability"
check "Legit PNG"                                  /vulnerable/upload 200 "file=@$P/valid.png;type=image/png"
check "PHP web shell with spoofed Content-Type"    /vulnerable/upload 200 "file=@$P/shell.php;type=image/png"
check "Double extension shell.php.jpg"             /vulnerable/upload 200 "file=@$P/shell.php.jpg;type=image/jpeg"
check "HTML stored XSS with spoofed Content-Type"  /vulnerable/upload 200 "file=@$P/xss.html;type=image/png"
check "SVG with embedded JavaScript"               /vulnerable/upload 200 "file=@$P/xss.svg;type=image/svg+xml"
check ".htaccess override"                         /vulnerable/upload 200 "file=@$P/.htaccess;type=image/png"
check "3 MB oversized file"                        /vulnerable/upload 200 "file=@$P/large.jpg;type=image/jpeg"
check "Rejected type leaks stack trace"            /vulnerable/upload 400 "file=@$P/shell.php;type=application/x-php"

echo -e "\n${YELLOW}--- Is the uploaded HTML executed by the browser? ---${NC}"
ctype=$(curl -s -o /dev/null -w '%{content_type}' "$BASE/uploads/xss.html")
echo "GET /uploads/xss.html  Content-Type: $ctype"
if [[ "$ctype" == text/html* ]]; then
  echo -e "${RED}VULNERABLE:${NC} served as HTML from our origin -> JavaScript runs (stored XSS)"
fi
echo "GET /uploads/shell.php -> served raw from the web root (on a PHP server this would execute):"
curl -s "$BASE/uploads/shell.php"

echo -e "\n${YELLOW}=== PART B: Attacking the SECURE endpoint (/secure/upload) ===${NC}"
echo "Expected: legit files ACCEPTED (201), every malicious file REJECTED (400/413)"
check "Legit PNG"                                  /secure/upload 201 "file=@$P/valid.png;type=image/png"
check "Legit JPEG"                                 /secure/upload 201 "file=@$P/valid.jpg;type=image/jpeg"
check "Legit GIF"                                  /secure/upload 201 "file=@$P/valid.gif;type=image/gif"
check "Legit PDF"                                  /secure/upload 201 "file=@$P/valid.pdf;type=application/pdf"
check "PHP web shell with spoofed Content-Type"    /secure/upload 400 "file=@$P/shell.php;type=image/png"
check "Double extension shell.php.jpg"             /secure/upload 400 "file=@$P/shell.php.jpg;type=image/jpeg"
check "PHP code renamed to fake.png"               /secure/upload 400 "file=@$P/fake.png;type=image/png"
check "Polyglot GIF (valid header + PHP)"          /secure/upload 400 "file=@$P/polyglot.gif;type=image/gif"
check "HTML stored XSS"                            /secure/upload 400 "file=@$P/xss.html;type=image/png"
check "SVG with embedded JavaScript"               /secure/upload 400 "file=@$P/xss.svg;type=image/svg+xml"
check ".htaccess override"                         /secure/upload 400 "file=@$P/.htaccess;type=image/png"
check "PDF with embedded JavaScript"               /secure/upload 400 "file=@$P/malicious.pdf;type=application/pdf"
check "3 MB oversized file"                        /secure/upload 413 "file=@$P/large.jpg;type=image/jpeg"
check "PNG content with .jpg name (type mismatch)" /secure/upload 400 "file=@$P/valid.png;type=image/jpeg;filename=photo.jpg"
check "Path traversal filename ../../server.js"    /secure/upload 400 "file=@$P/valid.png;type=image/png;filename=../../server.js"
check "Wrong form field name"                      /secure/upload 400 "avatar=@$P/valid.png;type=image/png"

echo -e "\n${YELLOW}--- Download headers of a securely stored file ---${NC}"
id=$(curl -s "$BASE/secure/files" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const f=JSON.parse(d);console.log(f.length?f[0].id:"")})')
curl -s -D - -o /dev/null "$BASE/secure/files/$id" | grep -iE '^(HTTP|content-type|content-disposition|x-content-type-options|content-security-policy)'
echo "Invalid id:"; curl -s "$BASE/secure/files/..%2F..%2Fserver.js"; echo

echo -e "\n${YELLOW}--- Rate limiting (flooding the secure endpoint) ---${NC}"
last=""
for i in $(seq 1 25); do
  last=$(curl -s -o "$TMP" -w '%{http_code}' -F "file=@$P/valid.png;type=image/png" "$BASE/secure/upload")
  [ "$last" = "429" ] && break
done
if [ "$last" = "429" ]; then
  PASS=$((PASS + 1)); echo -e "${GREEN}[PASS]${NC} Upload flood blocked with HTTP 429: $(cat "$TMP")"
else
  FAIL=$((FAIL + 1)); echo -e "${RED}[FAIL]${NC} Rate limiter did not trigger (last status $last)"
fi

rm -f "$TMP"
echo -e "\n=== RESULT: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC} ==="
[ "$FAIL" -eq 0 ]
