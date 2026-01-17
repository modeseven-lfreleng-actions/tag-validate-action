#!/bin/bash

# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

# SSH Key Test Script for tag-validate CLI
# Tests various SSH key formats and fingerprint inputs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Test configuration
TEST_USER="mwatkins@linuxfoundation.org"
CLI_CMD="tag-validate github"

echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}                           SSH Key Test Script${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo
echo -e "${CYAN}Purpose:${NC} Test SSH key fingerprint parsing and normalization"
echo -e "${CYAN}Command:${NC} ${YELLOW}tag-validate github [KEY] -o [USER] --test-mode${NC}"
echo -e "${CYAN}Note:${NC} Using --test-mode flag to test parsing without GitHub API calls"
echo
printf "%-60s %s\n" "Key ID" "Parsing/Result"
printf '%*s\n' 70 '' | tr ' ' '-'

# Function to test a key
test_key() {
    local key_input="$1"
    local description="$2"
    local expected_result="$3"  # "pass" or "fail"

    printf "%-60s " "'$description'"

    # Run the command in test mode and capture both stdout and stderr
    if timeout 10s "$CLI_CMD" "$key_input" -o "$TEST_USER" --test-mode >/dev/null 2>&1; then
        if [ "$expected_result" = "pass" ]; then
            echo -e "${GREEN}✅${NC}"
        else
            echo -e "${YELLOW}✅ (unexpected pass)${NC}"
        fi
    else
        exit_code=$?
        if [ "$expected_result" = "fail" ] || [ $exit_code -eq 124 ]; then  # 124 is timeout
            if [ $exit_code -eq 124 ]; then
                echo -e "${YELLOW}⏱️  (timeout)${NC}"
            else
                echo -e "${RED}❌${NC}"
            fi
        else
            echo -e "${YELLOW}❌ (unexpected fail)${NC}"
        fi
    fi
}

# Test 1: SHA256 fingerprints (most common format)
test_key "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14" "SHA256:dAq...A14 (ECDSA-256)" "pass"
test_key "SHA256:lSpWQv6rFamTP2i93lIaLO8s8TZg/t06GsxrjQ5GAXY" "SHA256:lSp...AXY (ECDSA-384)" "pass"
test_key "SHA256:oitgrhcEWqRZ248fv26IaaN8TT26bXTr6y65ylS/EcI" "SHA256:oit...EcI (ECDSA-521)" "pass"
test_key "SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk" "SHA256:+gf...6wk (Ed25519)" "pass"
test_key "SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk" "SHA256:Q9U...zwk (RSA-2048)" "pass"
test_key "SHA256:xzmyjKD2ZBtadsgr2q0Bzu9B5sw4nAFeu69ZMb1MKNA" "SHA256:xzm...MNA (RSA-4096)" "pass"

# Test 2: Algorithm prefixed fingerprints
test_key "ECDSA:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14" "ECDSA:SHA256:dAq...A14" "pass"
test_key "ED25519:SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk" "ED25519:SHA256:+gf...6wk" "pass"
test_key "RSA:SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk" "RSA:SHA256:Q9U...zwk" "pass"

# Test 3: MD5 fingerprints (legacy format)
test_key "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3" "MD5:cf:19:30... (ECDSA-256)" "pass"
test_key "MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77" "MD5:f9:f3:44... (Ed25519)" "pass"
test_key "MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81" "MD5:da:21:bd... (RSA-2048)" "pass"

# Test 4: Algorithm prefixed MD5 fingerprints
test_key "ECDSA:MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3" "ECDSA:MD5:cf:19:30..." "pass"
test_key "ED25519:MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77" "ED25519:MD5:f9:f3:44..." "pass"
test_key "RSA:MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81" "RSA:MD5:da:21:bd..." "pass"

# Test 5: Full public keys
test_key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmDKuTvCuWLU59NtoBrYAqlzBHuR4MRB5KZonQyvGq" "ssh-ed25519 AAAAC3... (full key)" "pass"
test_key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNYFI6ZZhgGaRmjg3RpcmgbJ8txCUx8NtW9Zp/vdwJTyrc0q/qqEhYWYjLxwvoFIz4Gsue33ohPjetDFKmIpmMT3bOyYORB+AL5ByYZVuvKwtJw38tTZ112tDGrKAd61JjGfWjGbBW4pZqalUfAxP29GB7B5YyrFbvMpyS4GtBlND/FcakxEtxJKFoIHmGuXk/xvWoEf2B2x7zOm57P5vt0HT60BRRF0zYRYznl//2NcViBzdHIwGqUgO0M34pOKQIfogwEdGU8GW7pTyRssX36j1s5iC+xoq9AIijHrLM+1XtEmENk3u6tn0fGySjYcTx05mR9KhL8nZpT5AWohjz" "ssh-rsa AAAAB3... (full key)" "pass"

# Test 6: Invalid/malformed inputs
test_key "invalid-key-format" "invalid-key-format" "fail"
test_key "SHA256:" "SHA256: (empty)" "fail"
test_key "SHA256:InvalidBase64!" "SHA256:InvalidBase64!" "fail"
test_key "MD5:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz" "MD5:zz:zz... (invalid hex)" "fail"

# Test 7: Edge cases
test_key "" "empty string" "fail"
test_key "   " "whitespace only" "fail"
test_key "ssh-" "ssh- prefix only" "fail"

# Test 8: Test the actual working fingerprint (should pass)
test_key "ECDSA:SHA256:ZdI8Rev5CBKfs3Uywh3Nta59BfXcqiQ/3tG0pdjY/5Q" "ECDSA:SHA256:ZdI...5Q (known key)" "pass"

echo
echo -e "${BLUE}Test Summary:${NC}"
echo "- ✅ = Key parsing and normalization successful"
echo "- ❌ = Key parsing failed or unknown format"
echo "- All valid keys should show ✅ (successful parsing)"
echo "- Invalid/malformed keys should show ❌ (parsing failed)"
echo "- Test mode validates parsing without making GitHub API calls"
echo "- Any parsing errors indicate issues with key normalization logic"
