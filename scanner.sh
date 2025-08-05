#!/bin/bash

# Web Vulnerability Scanner Script
# Fixed version that scans ALL domains in the input file
# Maintains controlled concurrency with proper process waiting

# Exit codes
SUCCESS=0
ERR_MISSING_TOOL=1
ERR_INVALID_INPUT=2
ERR_CONFIG_FILE=3
ERR_TEMPLATE_PATH=4
ERR_PROCESSING=5
ERR_TIMEOUT=6

# Default configuration
CONCURRENCY=3
TIMEOUT=3600
VERBOSITY=1
CLEANUP=false
WAYMORE_CONFIG="${HOME}/automation/dast/config.yaml"
NUCLEI_DAST_TEMPLATES="${HOME}/nuclei-templates/dast"
NUCLEI_EXPOSURES_TEMPLATES="${HOME}/nuclei-templates/http/exposures"
OUTPUT_DIR="scan_results"
GF_PATTERNS=("sqli" "ssrf" "lfi" "ssti" "redirect" "xss" "xxe")

show_usage() {
    echo "Usage: $0 [options] <domain_list_file>"
    echo ""
    echo "Options:"
    echo "  -c <num>     Set concurrency level (default: $CONCURRENCY)"
    echo "  -t <sec>     Set timeout in seconds (default: $TIMEOUT)"
    echo "  -o <dir>     Set output directory (default: $OUTPUT_DIR)"
    echo "  -w <file>    Set waymore config file (default: $WAYMORE_CONFIG)"
    echo "  -d <dir>     Set nuclei DAST templates directory (default: $NUCLEI_DAST_TEMPLATES)"
    echo "  -e <dir>     Set nuclei exposures templates directory (default: $NUCLEI_EXPOSURES_TEMPLATES)"
    echo "  -v <level>   Set verbosity level (0-3, default: $VERBOSITY)"
    echo "  -k           Enable cleanup of temporary files"
    echo "  -h           Show this help message"
    exit $SUCCESS
}

# Parse command line options
while getopts "c:t:o:w:d:e:v:kh" option; do
    case $option in
        c) CONCURRENCY="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        w) WAYMORE_CONFIG="$OPTARG" ;;
        d) NUCLEI_DAST_TEMPLATES="$OPTARG" ;;
        e) NUCLEI_EXPOSURES_TEMPLATES="$OPTARG" ;;
        v) VERBOSITY="$OPTARG" ;;
        k) CLEANUP=true ;;
        h) show_usage ;;
        *) show_usage ;;
    esac
done
shift $((OPTIND-1))

# Check for required domain list file
if [ $# -ne 1 ]; then
    echo "Error: Domain list file not specified"
    show_usage
fi

DOMAIN_LIST="$1"

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local base_domain="${3:-global}"
    
    if [ "$level" -le "$VERBOSITY" ]; then
        local level_label
        case "$level" in
            0) level_label="" ;;
            1) level_label="INFO" ;;
            2) level_label="VERBOSE" ;;
            3) level_label="DEBUG" ;;
        esac
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]${base_domain:+ [$base_domain]}${level_label:+ [$level_label]} $message" | tee -a "${OUTPUT_DIR}/scan.log"
    fi
}

# Domain validation
validate_domain() {
    local domain="$1"
    
    # Basic format check
    if [[ ! "$domain" =~ ^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    
    # Length check
    if [ ${#domain} -gt 253 ]; then
        return 1
    fi
    
    # Invalid characters check
    if [[ "$domain" =~ [^a-zA-Z0-9.-] ]]; then
        return 1
    fi
    
    # IP address check
    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    
    return 0
}

# Get base domain
get_base_domain() {
    local domain="$1"
    echo "$domain" | awk -F'.' '{print $(NF-1)"."$NF}'
}

# Check required tools
check_required_tools() {
    local tools=("waymore" "gf" "nuclei" "notify")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_message 0 "Error: Missing required tools: ${missing_tools[*]}"
        exit $ERR_MISSING_TOOL
    fi
}

# Check template paths
check_template_dirs() {
    if [ ! -d "$NUCLEI_DAST_TEMPLATES" ]; then
        log_message 0 "Error: Nuclei DAST template path $NUCLEI_DAST_TEMPLATES not found"
        exit $ERR_TEMPLATE_PATH
    fi
    
    if [ ! -d "$NUCLEI_EXPOSURES_TEMPLATES" ]; then
        log_message 0 "Error: Nuclei exposures template path $NUCLEI_EXPOSURES_TEMPLATES not found"
        exit $ERR_TEMPLATE_PATH
    fi
}

# Check waymore config
verify_waymore_config() {
    if [ ! -f "$WAYMORE_CONFIG" ]; then
        log_message 1 "Warning: waymore config $WAYMORE_CONFIG not found, using default settings"
        return 1
    fi
    return 0
}

# Check gf patterns
get_valid_gf_patterns() {
    local base_domain="$1"
    local valid_patterns=()
    
    for pattern in "${GF_PATTERNS[@]}"; do
        if gf "$pattern" /dev/null >/dev/null 2>&1; then
            valid_patterns+=("$pattern")
        else
            log_message 2 "$base_domain" "Warning: gf pattern '$pattern' not found, skipping"
        fi
    done
    
    echo "${valid_patterns[@]}"
}

# Process a single domain
scan_domain() {
    local domain="$1"
    local base_domain
    base_domain=$(get_base_domain "$domain")
    local domain_dir="${OUTPUT_DIR}/${base_domain}"
    local domain_output_dir="${domain_dir}/subdomains/${domain}"
    local all_urls_file="${domain_dir}/${base_domain}_all.txt"
    
    mkdir -p "$domain_output_dir"
    
    log_message 1 "$base_domain" "Starting scan for domain: $domain"
    
    # Build waymore command
    local waymore_cmd="waymore -i \"$domain\" -mode U -oU \"${domain_output_dir}/urls.txt\" --no-subs"
    if verify_waymore_config; then
        waymore_cmd="waymore -c \"$WAYMORE_CONFIG\" -i \"$domain\" -mode U -oU \"${domain_output_dir}/urls.txt\" --no-subs"
    fi

    # Run waymore with retries
    log_message 1 "$base_domain" "Running waymore for $domain"
    local attempt=1
    local max_attempts=3
    local success=false
    
    while [ $attempt -le $max_attempts ]; do
        log_message 2 "$base_domain" "Attempt $attempt/$max_attempts for waymore on $domain"
        
        timeout $TIMEOUT bash -c "$waymore_cmd" 2>> "${domain_output_dir}/error.log"
        local ret=$?
        
        if [ $ret -eq 0 ] && [ -s "${domain_output_dir}/urls.txt" ]; then
            success=true
            break
        elif [ $ret -eq 124 ]; then
            log_message 1 "$base_domain" "Waymore timed out for $domain (attempt $attempt/$max_attempts)"
        else
            log_message 1 "$base_domain" "Error running waymore for $domain (attempt $attempt/$max_attempts) - No URLs found"
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_message 1 "$base_domain" "Max attempts reached for $domain, moving to next domain"
            return $ERR_PROCESSING
        fi
        
        log_message 2 "$base_domain" "Waiting 30 seconds before retrying waymore for $domain"
        sleep 30
        ((attempt++))
    done

    if [ ! -s "${domain_output_dir}/urls.txt" ]; then
        log_message 1 "$base_domain" "No URLs found for $domain after all attempts"
        return $ERR_PROCESSING
    else
        local url_count
        url_count=$(wc -l < "${domain_output_dir}/urls.txt")
        log_message 1 "$base_domain" "Found $url_count URLs for $domain"
        cat "${domain_output_dir}/urls.txt" >> "$all_urls_file"
        log_message 2 "$base_domain" "Appended URLs to ${base_domain}_all.txt"
    fi

    # Run gf patterns
    local valid_patterns
    read -r -a valid_patterns <<< "$(get_valid_gf_patterns "$base_domain")"
    local combined_urls="${domain_output_dir}/vulnurls.txt"
    : > "$combined_urls"
    
    log_message 1 "$base_domain" "Running gf patterns for $domain"
    for pattern in "${valid_patterns[@]}"; do
        log_message 3 "$base_domain" "Running gf pattern: $pattern"
        grep -E "$pattern" "${domain_output_dir}/urls.txt" >> "$combined_urls" 2>> "${domain_output_dir}/error.log" || \
        log_message 2 "$base_domain" "Error running gf $pattern for $domain"
    done

    if [ -s "$combined_urls" ]; then
        sort -u "$combined_urls" -o "$combined_urls"
        local vuln_url_count
        vuln_url_count=$(wc -l < "$combined_urls")
        log_message 1 "$base_domain" "Found $vuln_url_count vulnerability URLs after gf for $domain"
    else
        log_message 1 "$base_domain" "No vulnerability URLs found after gf for $domain"
    fi

    # Run nuclei scans
    if [ -s "$combined_urls" ]; then
        log_message 1 "$base_domain" "Running nuclei DAST scan for $domain"
        timeout $TIMEOUT nuclei -l "$combined_urls" -t "$NUCLEI_DAST_TEMPLATES" -dast \
            -o "${domain_output_dir}/nuclei_dast_results.txt" 2>> "${domain_output_dir}/error.log" | \
            notify -silent 2>> "${domain_output_dir}/error.log" || \
            log_message 2 "$base_domain" "Error running nuclei DAST scan for $domain"
    fi

    # Check for sensitive files
    log_message 1 "$base_domain" "Checking for sensitive files in $domain"
    local sensitive_files="${domain_output_dir}/sensitive_files.txt"
    grep -E "\.(txt|log|cache|secret|db|backup|yml|json|gz|rar|zip|config|js|sql|env|sh|bash|history|git|svn|htaccess|htpasswd|ini|conf|xml|php|asp|aspx|jsp|py|rb|pl|cgi|swf|bak|old|temp|tmp)$" \
        "${domain_output_dir}/urls.txt" > "$sensitive_files" 2>> "${domain_output_dir}/error.log"
    
    if [ -s "$sensitive_files" ]; then
        local sensitive_count
        sensitive_count=$(wc -l < "$sensitive_files")
        log_message 1 "$base_domain" "Found $sensitive_count sensitive files for $domain"
        
        log_message 1 "$base_domain" "Running nuclei exposures scan for $domain"
        timeout $TIMEOUT nuclei -l "$sensitive_files" -t "$NUCLEI_EXPOSURES_TEMPLATES" \
            -o "${domain_output_dir}/nuclei_exposures_results.txt" 2>> "${domain_output_dir}/error.log" | \
            notify -silent 2>> "${domain_output_dir}/error.log" || \
            log_message 2 "$base_domain" "Error running nuclei exposures scan for $domain"
    else
        log_message 2 "$base_domain" "No sensitive files found for $domain"
    fi

    # Cleanup if requested
    if $CLEANUP; then
        log_message 2 "$base_domain" "Cleaning up temporary files for $domain"
        rm -f "$combined_urls" "$sensitive_files"
    else
        log_message 3 "$base_domain" "Keeping all temporary files for $domain"
    fi

    # Finalize all URLs file
    if [ -f "$all_urls_file" ]; then
        sort -u "$all_urls_file" -o "$all_urls_file"
        log_message 2 "$base_domain" "Consolidated all URLs for $base_domain into $all_urls_file"
    fi

    log_message 1 "$base_domain" "Completed processing for $domain"
    return $SUCCESS
}

# Main script execution
main() {
    check_required_tools
    check_template_dirs

    if [ ! -f "$DOMAIN_LIST" ]; then
        log_message 0 "Error: Domain list file $DOMAIN_LIST not found"
        exit $ERR_INVALID_INPUT
    fi

    # Prepare output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Clean domain list
    log_message 1 "global" "Cleaning domain list"
    grep -E '^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$' "$DOMAIN_LIST" > "${OUTPUT_DIR}/domains_clean.txt"
    mv "${OUTPUT_DIR}/domains_clean.txt" "$DOMAIN_LIST"
    log_message 1 "global" "Domain list cleaned"

    local total_domains
    total_domains=$(wc -l < "$DOMAIN_LIST")
    log_message 1 "global" "Total domains to process: $total_domains"

    # Process domains with proper concurrency control
    local counter=0
    local pids=()
    
    while read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]')
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        
        if validate_domain "$domain"; then
            ((counter++))
            scan_domain "$domain" &
            pids+=($!)
            
            # When we hit concurrency limit, wait for one process to finish
            if (( counter % CONCURRENCY == 0 )); then
                wait -n
            fi
        else
            log_message 1 "global" "Skipping invalid domain: $domain"
        fi
    done < "$DOMAIN_LIST"
    
    # Wait for all remaining processes
    wait "${pids[@]}"
    
    log_message 1 "global" "Processing complete. Domains processed: $counter/$total_domains"
    exit $SUCCESS
}

# Start the script
main
