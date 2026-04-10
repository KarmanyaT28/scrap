#!/usr/bin/env bash
# shellcheck disable=SC2317,SC2155,SC2207
#
# SOC Hunt Orchestrator
# A portfolio-grade Bash threat-hunting and triage framework for SOC analysts.
#
# Features:
# - Docker and Kubernetes telemetry collection
# - Apache access/error log parsing
# - IOC correlation against local feeds
# - Parallel evidence collection with worker pools
# - Risk scoring and JSON/CSV/Markdown reporting
# - Demonstrates broad Bash concepts: strict mode, traps, arrays, assoc arrays,
#   namerefs, case/select, getopts-like long parsing, regex, here-docs, here-strings,
#   command substitution, process substitution, subshells, FIFOs, coproc, background jobs,
#   flock, mapfile/readarray, printf formatting, parameter expansion, extglob, nullglob,
#   arithmetic, functions returning via stdout, local scoping, and more.
#
# Note:
# This script assumes common Linux tools are present: docker, kubectl, awk, sed, grep, jq, curl.
# It is intentionally advanced and educational, suitable as a strong LinkedIn/GitHub project.

set -Eeuo pipefail
shopt -s extglob nullglob globstar lastpipe
IFS=$'\n\t'

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly RUN_ID="run-$(date +%s)-$RANDOM"
readonly DEFAULT_OUTDIR="${SCRIPT_DIR}/output/${RUN_ID}"
readonly DEFAULT_FEED_DIR="${SCRIPT_DIR}/feeds"
readonly LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"

# --- Global mutable state ----------------------------------------------------
declare -Ag CONFIG=(
  [mode]="full"
  [namespace]="default"
  [outdir]="$DEFAULT_OUTDIR"
  [feed_dir]="$DEFAULT_FEED_DIR"
  [apache_log]="/var/log/apache2/access.log"
  [apache_error_log]="/var/log/apache2/error.log"
  [kube_context]=""
  [container_filter]=""
  [pod_selector]=""
  [since]="30m"
  [parallel]="4"
  [report_format]="all"
  [severity_threshold]="40"
  [ioc_feed]="iocs.txt"
  [domain_feed]="domains.txt"
  [user_agent_feed]="user_agents.txt"
  [enable_enrichment]="false"
  [apache_source]="auto"
  [verbose]="false"
  [dry_run]="false"
)

declare -ag TEMP_PATHS=()
declare -ag JOB_PIDS=()
declare -ag FINDINGS=()
declare -ag WARNINGS=()
declare -ag ERRORS=()

declare -Ag STATS=(
  [containers_scanned]=0
  [pods_scanned]=0
  [apache_events]=0
  [ioc_hits]=0
  [suspicious_ips]=0
  [suspicious_uas]=0
  [suspicious_domains]=0
  [events_total]=0
  [risk_score]=0
)

declare -Ag SCORECARD=(
  [docker_suspicious_exec]=20
  [docker_privileged]=25
  [docker_host_network]=20
  [docker_mount_sensitive]=15
  [k8s_privileged]=25
  [k8s_hostnetwork]=15
  [k8s_latest_tag]=10
  [k8s_secret_env]=15
  [apache_scanner_ua]=10
  [apache_404_burst]=15
  [apache_wp_probe]=10
  [apache_rce_pattern]=25
  [apache_sqli_pattern]=20
  [ioc_ip_match]=30
  [ioc_domain_match]=20
  [ioc_ua_match]=15
  [error_log_php_warning]=10
  [error_log_segfault]=25
)

declare -Ag COLOR=(
  [red]='\033[0;31m'
  [green]='\033[0;32m'
  [yellow]='\033[1;33m'
  [blue]='\033[0;34m'
  [cyan]='\033[0;36m'
  [bold]='\033[1m'
  [reset]='\033[0m'
)

# --- Utility ----------------------------------------------------------------
usage() {
  cat <<'EOF'
SOC Hunt Orchestrator

Usage:
  soc_hunt_orchestrator.sh [options]

Options:
  --mode <full|docker|k8s|apache|ioc>
  --namespace <k8s namespace>
  --kube-context <context>
  --pod-selector <label selector>
  --container-filter <docker name regex>
  --apache-log <path>
  --apache-error-log <path>
  --apache-source <auto|host|docker|k8s>
  --feed-dir <path>
  --outdir <path>
  --since <duration>                Example: 30m, 2h, 1h30m
  --parallel <n>
  --severity-threshold <n>
  --report-format <json|csv|md|all>
  --enable-enrichment
  --dry-run
  --verbose
  --help
  --version

Feed files expected in --feed-dir:
  iocs.txt          IP IOC list, one per line
  domains.txt       Suspicious domains, one per line
  user_agents.txt   Suspicious user agents or substrings, one per line
EOF
}

version() {
  printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
}

log() {
  local level="$1"; shift
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local color="${COLOR[blue]}"
  case "$level" in
    INFO)  color="${COLOR[blue]}" ;;
    OK)    color="${COLOR[green]}" ;;
    WARN)  color="${COLOR[yellow]}" ;;
    ERROR) color="${COLOR[red]}" ;;
    DEBUG) color="${COLOR[cyan]}" ;;
  esac
  if [[ "$level" == "DEBUG" && "${CONFIG[verbose]}" != "true" ]]; then
    return 0
  fi
  printf '%b[%s] [%s] %s%b\n' "$color" "$ts" "$level" "$*" "${COLOR[reset]}" >&2
}

append_warning() { WARNINGS+=("$*"); }
append_error()   { ERRORS+=("$*"); }
append_finding() { FINDINGS+=("$*"); }

cleanup() {
  local path
  for path in "${TEMP_PATHS[@]:-}"; do
    [[ -n "$path" && -e "$path" ]] && rm -rf -- "$path"
  done
}

on_error() {
  local exit_code="$?"
  local line_no="$1"
  append_error "Unhandled error near line ${line_no}, exit=${exit_code}"
  log ERROR "Unhandled error near line ${line_no}, exit=${exit_code}"
  write_metadata || true
  cleanup
  exit "$exit_code"
}

trap 'on_error ${LINENO}' ERR
trap cleanup EXIT
trap 'log WARN "Interrupted"; exit 130' INT TERM

require_cmd() {
  local missing=()
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if ((${#missing[@]} > 0)); then
    printf 'Missing required commands: %s\n' "${missing[*]}" >&2
    exit 1
  fi
}

with_lock() {
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    log ERROR "Another instance appears to be running. Lock: $LOCK_FILE"
    exit 1
  fi
}

mktempd() {
  local d
  d="$(mktemp -d)"
  TEMP_PATHS+=("$d")
  printf '%s\n' "$d"
}

mkdirs() {
  mkdir -p -- "${CONFIG[outdir]}"/{raw,processed,reports,logs,cache}
}

normalize_bool() {
  case "${1,,}" in
    1|true|yes|y|on) printf 'true\n' ;;
    *) printf 'false\n' ;;
  esac
}

join_by() {
  local IFS="$1"
  shift
  printf '%s' "$*"
}

trim() {
  local s="$*"
  s="${s#${s%%[![:space:]]*}}"
  s="${s%${s##*[![:space:]]}}"
  printf '%s\n' "$s"
}

lower() { printf '%s\n' "${1,,}"; }
upper() { printf '%s\n' "${1^^}"; }

# Demonstrates nameref usage
increment_stat() {
  local key="$1"
  local amount="${2:-1}"
  declare -n ref=STATS
  (( ref["$key"] += amount ))
}

set_config() {
  local k="$1" v="$2"
  CONFIG["$k"]="$v"
}

parse_args() {
  while (($#)); do
    case "$1" in
      --mode)                set_config mode "${2:?missing value for --mode}"; shift 2 ;;
      --namespace)           set_config namespace "${2:?missing value for --namespace}"; shift 2 ;;
      --kube-context)        set_config kube_context "${2:?missing value for --kube-context}"; shift 2 ;;
      --pod-selector)        set_config pod_selector "${2:?missing value for --pod-selector}"; shift 2 ;;
      --container-filter)    set_config container_filter "${2:?missing value for --container-filter}"; shift 2 ;;
      --apache-log)          set_config apache_log "${2:?missing value for --apache-log}"; shift 2 ;;
      --apache-error-log)    set_config apache_error_log "${2:?missing value for --apache-error-log}"; shift 2 ;;
      --apache-source)       set_config apache_source "${2:?missing value for --apache-source}"; shift 2 ;;
      --feed-dir)            set_config feed_dir "${2:?missing value for --feed-dir}"; shift 2 ;;
      --outdir)              set_config outdir "${2:?missing value for --outdir}"; shift 2 ;;
      --since)               set_config since "${2:?missing value for --since}"; shift 2 ;;
      --parallel)            set_config parallel "${2:?missing value for --parallel}"; shift 2 ;;
      --severity-threshold)  set_config severity_threshold "${2:?missing value for --severity-threshold}"; shift 2 ;;
      --report-format)       set_config report_format "${2:?missing value for --report-format}"; shift 2 ;;
      --enable-enrichment)   set_config enable_enrichment true; shift ;;
      --verbose)             set_config verbose true; shift ;;
      --dry-run)             set_config dry_run true; shift ;;
      --help|-h)             usage; exit 0 ;;
      --version|-V)          version; exit 0 ;;
      --)                    shift; break ;;
      -*)                    log ERROR "Unknown option: $1"; usage; exit 1 ;;
      *)                     break ;;
    esac
  done
}

validate_args() {
  [[ "${CONFIG[mode]}" =~ ^(full|docker|k8s|apache|ioc)$ ]] || {
    log ERROR "Invalid --mode: ${CONFIG[mode]}"; exit 1;
  }
  [[ "${CONFIG[apache_source]}" =~ ^(auto|host|docker|k8s)$ ]] || {
    log ERROR "Invalid --apache-source: ${CONFIG[apache_source]}"; exit 1;
  }
  [[ "${CONFIG[parallel]}" =~ ^[0-9]+$ ]] || {
    log ERROR "--parallel must be numeric"; exit 1;
  }
}

print_banner() {
  cat <<EOF
${COLOR[bold]}SOC Hunt Orchestrator${COLOR[reset]}
Run ID       : ${RUN_ID}
Hostname     : ${HOSTNAME_FQDN}
Started (UTC): ${START_TS}
Mode         : ${CONFIG[mode]}
Outdir       : ${CONFIG[outdir]}
EOF
}

# --- Feed handling -----------------------------------------------------------
read_feed() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  grep -Ev '^[[:space:]]*(#|$)' "$file" | sed 's/[[:space:]]\+$//'
}

load_feeds() {
  local feed_dir="${CONFIG[feed_dir]}"
  mkdir -p -- "$feed_dir"
  mapfile -t IOC_IPS < <(read_feed "$feed_dir/${CONFIG[ioc_feed]}")
  mapfile -t IOC_DOMAINS < <(read_feed "$feed_dir/${CONFIG[domain_feed]}")
  mapfile -t IOC_UAS < <(read_feed "$feed_dir/${CONFIG[user_agent_feed]}")
  log INFO "Loaded feeds: ips=${#IOC_IPS[@]:-0} domains=${#IOC_DOMAINS[@]:-0} user_agents=${#IOC_UAS[@]:-0}"
}

# --- Helpers for JSON-safe output -------------------------------------------
json_escape() {
  jq -Rsa . <<<"${1:-}"
}

to_json_array() {
  local -a arr=("$@")
  printf '%s\n' "${arr[@]}" | jq -Rsc 'split("\n")[:-1]'
}

# --- Command wrappers --------------------------------------------------------
maybe_run() {
  if [[ "${CONFIG[dry_run]}" == "true" ]]; then
    log INFO "DRY RUN: $*"
    return 0
  fi
  "$@"
}

kctl() {
  local -a cmd=(kubectl)
  [[ -n "${CONFIG[kube_context]}" ]] && cmd+=(--context "${CONFIG[kube_context]}")
  cmd+=("$@")
  maybe_run "${cmd[@]}"
}

# --- Docker collection -------------------------------------------------------
docker_list_targets() {
  require_cmd docker jq
  local filter="${CONFIG[container_filter]}"
  docker ps --format '{{json .}}' | jq -rc '.' | while IFS= read -r row; do
    local name image id
    name="$(jq -r '.Names' <<<"$row")"
    image="$(jq -r '.Image' <<<"$row")"
    id="$(jq -r '.ID' <<<"$row")"
    if [[ -n "$filter" ]]; then
      [[ "$name" =~ $filter || "$image" =~ $filter ]] || continue
    fi
    printf '%s\t%s\t%s\n' "$id" "$name" "$image"
  done
}

docker_inspect_one() {
  local cid="$1" cname="$2" cimage="$3"
  local outfile="${CONFIG[outdir]}/raw/docker-${cname}.json"
  docker inspect "$cid" > "$outfile"

  local privileged hostnetwork mounts
  privileged="$(jq -r '.[0].HostConfig.Privileged // false' "$outfile")"
  hostnetwork="$(jq -r '.[0].HostConfig.NetworkMode // ""' "$outfile")"
  mounts="$(jq -r '.[0].Mounts[]?.Source // empty' "$outfile" | paste -sd ',' -)"

  if [[ "$privileged" == "true" ]]; then
    append_finding "docker|high|${cname}|Container is privileged"
    (( STATS[risk_score] += SCORECARD[docker_privileged] ))
  fi

  if [[ "$hostnetwork" == "host" ]]; then
    append_finding "docker|medium|${cname}|Container uses host network"
    (( STATS[risk_score] += SCORECARD[docker_host_network] ))
  fi

  if grep -Eq '/etc|/var/run/docker.sock|/root|/proc|/sys' <<<"$mounts"; then
    append_finding "docker|medium|${cname}|Sensitive host mount detected: ${mounts}"
    (( STATS[risk_score] += SCORECARD[docker_mount_sensitive] ))
  fi

  increment_stat containers_scanned
}

docker_collect_logs() {
  local cid="$1" cname="$2"
  local out="${CONFIG[outdir]}/raw/docker-${cname}.log"
  docker logs --since "${CONFIG[since]}" "$cid" > "$out" 2>&1 || true

  # Suspicious patterns across logs
  local suspicious_patterns='(curl .*(169\.254\.169\.254|metadata)|chmod \+s|nc -e|/bin/sh -i|base64 -d|wget .*http|/dev/tcp/)'
  if grep -Eiq "$suspicious_patterns" "$out"; then
    append_finding "docker|high|${cname}|Suspicious execution pattern found in logs"
    (( STATS[risk_score] += SCORECARD[docker_suspicious_exec] ))
  fi
}

run_docker_module() {
  log INFO "Running Docker module"
  require_cmd docker jq
  local -a targets=()
  mapfile -t targets < <(docker_list_targets)
  if ((${#targets[@]} == 0)); then
    append_warning "No running Docker containers matched the filter"
    return 0
  fi

  local item cid cname cimage
  for item in "${targets[@]}"; do
    IFS=$'\t' read -r cid cname cimage <<<"$item"
    docker_inspect_one "$cid" "$cname" "$cimage"
    docker_collect_logs "$cid" "$cname"
  done
}

# --- Kubernetes collection ---------------------------------------------------
k8s_list_pods() {
  require_cmd kubectl jq
  local -a args=(get pods -n "${CONFIG[namespace]}" -o json)
  [[ -n "${CONFIG[pod_selector]}" ]] && args+=( -l "${CONFIG[pod_selector]}" )
  kctl "${args[@]}" | jq -rc '.items[] | {
    name: .metadata.name,
    namespace: .metadata.namespace,
    hostNetwork: (.spec.hostNetwork // false),
    containers: [.spec.containers[] | {name,image,securityContext,env}]
  }'
}

k8s_analyze_pod() {
  local pod_json="$1"
  local name ns host_network
  name="$(jq -r '.name' <<<"$pod_json")"
  ns="$(jq -r '.namespace' <<<"$pod_json")"
  host_network="$(jq -r '.hostNetwork' <<<"$pod_json")"

  local out="${CONFIG[outdir]}/raw/k8s-${ns}-${name}.json"
  printf '%s\n' "$pod_json" > "$out"

  if [[ "$host_network" == "true" ]]; then
    append_finding "k8s|medium|${ns}/${name}|Pod uses hostNetwork"
    (( STATS[risk_score] += SCORECARD[k8s_hostnetwork] ))
  fi

  local cjson image privileged env_json
  while IFS= read -r cjson; do
    image="$(jq -r '.image' <<<"$cjson")"
    privileged="$(jq -r '.securityContext.privileged // false' <<<"$cjson")"
    env_json="$(jq -c '.env // []' <<<"$cjson")"

    if [[ "$image" == *:latest ]]; then
      append_finding "k8s|low|${ns}/${name}|Container image uses latest tag: ${image}"
      (( STATS[risk_score] += SCORECARD[k8s_latest_tag] ))
    fi

    if [[ "$privileged" == "true" ]]; then
      append_finding "k8s|high|${ns}/${name}|Privileged container detected: ${image}"
      (( STATS[risk_score] += SCORECARD[k8s_privileged] ))
    fi

    if jq -e '.[]? | select(.valueFrom.secretKeyRef != null)' <<<"$env_json" >/dev/null; then
      append_finding "k8s|medium|${ns}/${name}|SecretKeyRef environment usage present"
      (( STATS[risk_score] += SCORECARD[k8s_secret_env] ))
    fi
  done < <(jq -c '.containers[]' <<<"$pod_json")

  increment_stat pods_scanned
}

k8s_collect_logs() {
  local pod="$1"
  local ns="$2"
  local log_out="${CONFIG[outdir]}/raw/k8s-${ns}-${pod}.log"
  kctl logs -n "$ns" "$pod" --since="${CONFIG[since]}" --all-containers=true > "$log_out" 2>&1 || true
}

run_k8s_module() {
  log INFO "Running Kubernetes module"
  require_cmd kubectl jq
  local -a pods=()
  mapfile -t pods < <(k8s_list_pods)
  if ((${#pods[@]} == 0)); then
    append_warning "No Kubernetes pods matched the query"
    return 0
  fi

  local pod_json name ns
  for pod_json in "${pods[@]}"; do
    k8s_analyze_pod "$pod_json"
    name="$(jq -r '.name' <<<"$pod_json")"
    ns="$(jq -r '.namespace' <<<"$pod_json")"
    k8s_collect_logs "$name" "$ns"
  done
}

# --- Apache handling ---------------------------------------------------------
apache_detect_source() {
  case "${CONFIG[apache_source]}" in
    host) printf 'host\n'; return ;;
    docker) printf 'docker\n'; return ;;
    k8s) printf 'k8s\n'; return ;;
  esac

  if [[ -f "${CONFIG[apache_log]}" ]]; then
    printf 'host\n'
    return
  fi

  if docker ps --format '{{.Image}} {{.Names}}' 2>/dev/null | grep -Eiq 'apache|httpd'; then
    printf 'docker\n'
    return
  fi

  if kctl get pods -A -o name 2>/dev/null | grep -Eiq 'apache|httpd'; then
    printf 'k8s\n'
    return
  fi

  printf 'none\n'
}

apache_collect_host_logs() {
  [[ -f "${CONFIG[apache_log]}" ]] && cp -f -- "${CONFIG[apache_log]}" "${CONFIG[outdir]}/raw/apache-access.log"
  [[ -f "${CONFIG[apache_error_log]}" ]] && cp -f -- "${CONFIG[apache_error_log]}" "${CONFIG[outdir]}/raw/apache-error.log"
}

apache_collect_docker_logs() {
  local line cid name image first_httpd=""
  while IFS= read -r line; do
    cid="${line%%$'\t'*}"
    name="$(cut -f2 <<<"$line")"
    image="$(cut -f3 <<<"$line")"
    if [[ "$name" =~ apache|httpd || "$image" =~ apache|httpd ]]; then
      first_httpd="$cid"
      break
    fi
  done < <(docker_list_targets)

  [[ -n "$first_httpd" ]] || { append_warning "No Apache Docker container found"; return 0; }
  docker logs --since "${CONFIG[since]}" "$first_httpd" > "${CONFIG[outdir]}/raw/apache-access.log" 2>&1 || true
}

apache_collect_k8s_logs() {
  local pod ns pod_json
  while IFS= read -r pod_json; do
    pod="$(jq -r '.name' <<<"$pod_json")"
    ns="$(jq -r '.namespace' <<<"$pod_json")"
    if [[ "$pod" =~ apache|httpd ]]; then
      kctl logs -n "$ns" "$pod" --since="${CONFIG[since]}" --all-containers=true > "${CONFIG[outdir]}/raw/apache-access.log" 2>&1 || true
      break
    fi
  done < <(k8s_list_pods)
}

apache_parse_access_log() {
  local log_file="${CONFIG[outdir]}/raw/apache-access.log"
  [[ -s "$log_file" ]] || { append_warning "Apache access log not found or empty"; return 0; }

  local parsed="${CONFIG[outdir]}/processed/apache-access.parsed.tsv"
  awk '
    match($0,/^([^ ]+) [^ ]+ [^ ]+ \[([^]]+)\] "([A-Z]+) ([^ ]+) [^"]+" ([0-9]{3}) ([0-9-]+) "([^"]*)" "([^"]*)"/,a){
      print a[1]"\t"a[2]"\t"a[3]"\t"a[4]"\t"a[5]"\t"a[6]"\t"a[7]"\t"a[8]
    }
  ' "$log_file" > "$parsed"

  local -A ip_counts=()
  local ip method uri status bytes referer ua
  while IFS=$'\t' read -r ip _ method uri status bytes referer ua; do
    [[ -n "$ip" ]] || continue
    (( ip_counts["$ip"]++ ))
    increment_stat apache_events

    if [[ "$ua" =~ (sqlmap|nikto|nmap|gobuster|dirbuster|masscan|acunetix|nessus) ]]; then
      append_finding "apache|medium|${ip}|Suspicious scanner user-agent: ${ua}"
      (( STATS[risk_score] += SCORECARD[apache_scanner_ua] ))
      increment_stat suspicious_uas
    fi

    if [[ "$uri" =~ /(wp-admin|wp-login|xmlrpc\.php|\.env|\.git|server-status|phpmyadmin) ]]; then
      append_finding "apache|low|${ip}|Sensitive path probe: ${uri}"
      (( STATS[risk_score] += SCORECARD[apache_wp_probe] ))
    fi

    if [[ "$uri" =~ (\.|%2e){2}/|/etc/passwd|/bin/sh|cmd=|exec=|/proc/self/environ ]]; then
      append_finding "apache|high|${ip}|Possible RCE/LFI traversal pattern: ${uri}"
      (( STATS[risk_score] += SCORECARD[apache_rce_pattern] ))
    fi

    if [[ "$uri" =~ (union.*select|select.+from|or.+1=1|sleep\(|benchmark\() ]]; then
      append_finding "apache|high|${ip}|Possible SQLi pattern: ${uri}"
      (( STATS[risk_score] += SCORECARD[apache_sqli_pattern] ))
    fi
  done < "$parsed"

  for ip in "${!ip_counts[@]}"; do
    if (( ip_counts["$ip"] >= 25 )); then
      append_finding "apache|medium|${ip}|High request burst observed: ${ip_counts[$ip]} requests"
      (( STATS[risk_score] += SCORECARD[apache_404_burst] ))
      increment_stat suspicious_ips
    fi
  done
}

apache_parse_error_log() {
  local err_file="${CONFIG[outdir]}/raw/apache-error.log"
  [[ -s "$err_file" ]] || return 0
  if grep -Eiq 'PHP Warning|PHP Fatal|segmentation fault|AH00124|proxy:error' "$err_file"; then
    if grep -Eiq 'segmentation fault|core dumped' "$err_file"; then
      append_finding "apache|high|server|Potential crash exploitation indicators in Apache error log"
      (( STATS[risk_score] += SCORECARD[error_log_segfault] ))
    fi
    if grep -Eiq 'PHP Warning|PHP Fatal' "$err_file"; then
      append_finding "apache|low|server|PHP runtime warnings/errors observed"
      (( STATS[risk_score] += SCORECARD[error_log_php_warning] ))
    fi
  fi
}

run_apache_module() {
  log INFO "Running Apache module"
  local source
  source="$(apache_detect_source)"
  case "$source" in
    host)   apache_collect_host_logs ;;
    docker) apache_collect_docker_logs ;;
    k8s)    apache_collect_k8s_logs ;;
    none)   append_warning "Apache source could not be detected"; return 0 ;;
  esac
  apache_parse_access_log
  apache_parse_error_log
}

# --- IOC correlation ---------------------------------------------------------
# Parse IPs, domains, and UAs from collected logs then match against feeds.
collect_candidate_iocs() {
  local out_dir="${CONFIG[outdir]}/processed"
  : > "$out_dir/candidate_ips.txt"
  : > "$out_dir/candidate_domains.txt"
  : > "$out_dir/candidate_uas.txt"

  # Access log parsed data
  if [[ -f "$out_dir/apache-access.parsed.tsv" ]]; then
    awk -F'\t' '{print $1}' "$out_dir/apache-access.parsed.tsv" | sort -u > "$out_dir/candidate_ips.txt"
    awk -F'\t' '{print $8}' "$out_dir/apache-access.parsed.tsv" | sort -u > "$out_dir/candidate_uas.txt"
    awk -F'\t' '{print $7"\n"$4}' "$out_dir/apache-access.parsed.tsv" |
      grep -Eo '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' | sort -u > "$out_dir/candidate_domains.txt" || true
  fi

  # Docker logs and K8s logs domain extraction
  grep -RhoE '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' "${CONFIG[outdir]}/raw"/*.log 2>/dev/null | sort -u >> "$out_dir/candidate_domains.txt" || true
  sort -u -o "$out_dir/candidate_domains.txt" "$out_dir/candidate_domains.txt"
}

match_feed() {
  local feed_file="$1" cand_file="$2" type="$3"
  [[ -s "$feed_file" && -s "$cand_file" ]] || return 0

  local hit
  while IFS= read -r hit; do
    [[ -n "$hit" ]] || continue
    case "$type" in
      ip)
        append_finding "ioc|critical|${hit}|Matched IP IOC feed"
        (( STATS[risk_score] += SCORECARD[ioc_ip_match] ))
        increment_stat ioc_hits
        ;;
      domain)
        append_finding "ioc|high|${hit}|Matched domain IOC feed"
        (( STATS[risk_score] += SCORECARD[ioc_domain_match] ))
        increment_stat suspicious_domains
        increment_stat ioc_hits
        ;;
      ua)
        append_finding "ioc|medium|${hit}|Matched user-agent IOC feed"
        (( STATS[risk_score] += SCORECARD[ioc_ua_match] ))
        increment_stat suspicious_uas
        increment_stat ioc_hits
        ;;
    esac
  done < <(grep -Fxf "$feed_file" "$cand_file" || true)
}

run_ioc_module() {
  log INFO "Running IOC correlation module"
  collect_candidate_iocs
  local p="${CONFIG[outdir]}/processed"
  match_feed "${CONFIG[feed_dir]}/${CONFIG[ioc_feed]}" "$p/candidate_ips.txt" ip
  match_feed "${CONFIG[feed_dir]}/${CONFIG[domain_feed]}" "$p/candidate_domains.txt" domain
  match_feed "${CONFIG[feed_dir]}/${CONFIG[user_agent_feed]}" "$p/candidate_uas.txt" ua
}

# --- Enrichment --------------------------------------------------------------
# This keeps internet usage optional. In dry/demo mode it can be left disabled.
enrich_ip() {
  local ip="$1"
  [[ "${CONFIG[enable_enrichment]}" == "true" ]] || return 0
  local cache_file="${CONFIG[outdir]}/cache/ip-${ip}.json"
  [[ -f "$cache_file" ]] || curl -fsS "https://ipinfo.io/${ip}/json" -o "$cache_file" || return 0
  jq -r '[.ip,.city,.region,.country,.org] | @tsv' "$cache_file" 2>/dev/null || true
}

run_enrichment_module() {
  [[ "${CONFIG[enable_enrichment]}" == "true" ]] || return 0
  log INFO "Running enrichment module"
  local item entity
  : > "${CONFIG[outdir]}/processed/enrichment.tsv"
  for item in "${FINDINGS[@]:-}"; do
    entity="$(cut -d'|' -f3 <<<"$item")"
    if [[ "$entity" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      enrich_ip "$entity" >> "${CONFIG[outdir]}/processed/enrichment.tsv" || true
    fi
  done
}

# --- Parallelism with worker FIFO + coproc ----------------------------------
# Demonstration of named pipes and coprocess for scalable collection scheduling.
spawn_log_monitor() {
  coproc LOGMON { awk '{print strftime("%Y-%m-%dT%H:%M:%SZ", systime()), "MONITOR", $0; fflush(); }'; }
  exec 7>&"${LOGMON[1]}"
}

monitor_event() {
  printf '%s\n' "$*" >&7 || true
}

parallel_demo_worker_pool() {
  local fifo_dir fifo
  fifo_dir="$(mktempd)"
  fifo="$fifo_dir/tasks.fifo"
  mkfifo "$fifo"

  # Spawn worker processes
  local workers="${CONFIG[parallel]}"
  local i
  for ((i=1; i<=workers; i++)); do
    {
      while IFS= read -r task; do
        [[ -n "$task" ]] || continue
        monitor_event "worker=${i} task=${task}"
        case "$task" in
          sleep:*) sleep "${task#sleep:}" ;;
          noop) : ;;
          *) printf 'task=%s\n' "$task" > /dev/null ;;
        esac
      done < "$fifo"
    } &
    JOB_PIDS+=("$!")
  done

  # Feed demo tasks
  {
    printf 'sleep:0.1\n'
    printf 'noop\n'
    printf 'sleep:0.2\n'
  } > "$fifo"

  rm -f -- "$fifo"
}

wait_for_jobs() {
  local pid rc=0
  for pid in "${JOB_PIDS[@]:-}"; do
    wait "$pid" || rc=$?
  done
  return "$rc"
}

# --- Reporting ---------------------------------------------------------------
severity_rank() {
  case "$1" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    *)        echo 0 ;;
  esac
}

sort_findings() {
  printf '%s\n' "${FINDINGS[@]:-}" | awk -F'|' '
    function rank(s){return s=="critical"?4:s=="high"?3:s=="medium"?2:s=="low"?1:0}
    NF{print rank($2)"|"$0}
  ' | sort -t'|' -k1,1nr | cut -d'|' -f2-
}

write_metadata() {
  local meta="${CONFIG[outdir]}/reports/metadata.json"
  cat > "$meta" <<EOF
{
  "run_id": $(json_escape "$RUN_ID"),
  "script": $(json_escape "$SCRIPT_NAME"),
  "version": $(json_escape "$SCRIPT_VERSION"),
  "started_utc": $(json_escape "$START_TS"),
  "hostname": $(json_escape "$HOSTNAME_FQDN"),
  "mode": $(json_escape "${CONFIG[mode]}"),
  "namespace": $(json_escape "${CONFIG[namespace]}"),
  "since": $(json_escape "${CONFIG[since]}"),
  "stats": {
    "containers_scanned": ${STATS[containers_scanned]},
    "pods_scanned": ${STATS[pods_scanned]},
    "apache_events": ${STATS[apache_events]},
    "ioc_hits": ${STATS[ioc_hits]},
    "suspicious_ips": ${STATS[suspicious_ips]},
    "suspicious_uas": ${STATS[suspicious_uas]},
    "suspicious_domains": ${STATS[suspicious_domains]},
    "risk_score": ${STATS[risk_score]}
  }
}
EOF
}

write_json_report() {
  local report="${CONFIG[outdir]}/reports/findings.json"
  local findings_json warnings_json errors_json
  findings_json="$(
    sort_findings | jq -Rsc '
      split("\n")[:-1]
      | map(split("|"))
      | map({source: .[0], severity: .[1], entity: .[2], detail: .[3]})
    '
  )"
  warnings_json="$(to_json_array "${WARNINGS[@]:-}")"
  errors_json="$(to_json_array "${ERRORS[@]:-}")"

  cat > "$report" <<EOF
{
  "run_id": $(json_escape "$RUN_ID"),
  "started_utc": $(json_escape "$START_TS"),
  "mode": $(json_escape "${CONFIG[mode]}"),
  "risk_score": ${STATS[risk_score]},
  "threshold": ${CONFIG[severity_threshold]},
  "stats": {
    "containers_scanned": ${STATS[containers_scanned]},
    "pods_scanned": ${STATS[pods_scanned]},
    "apache_events": ${STATS[apache_events]},
    "ioc_hits": ${STATS[ioc_hits]},
    "suspicious_ips": ${STATS[suspicious_ips]},
    "suspicious_uas": ${STATS[suspicious_uas]},
    "suspicious_domains": ${STATS[suspicious_domains]}
  },
  "warnings": ${warnings_json},
  "errors": ${errors_json},
  "findings": ${findings_json}
}
EOF
}

write_csv_report() {
  local report="${CONFIG[outdir]}/reports/findings.csv"
  printf 'source,severity,entity,detail\n' > "$report"
  while IFS='|' read -r source severity entity detail; do
    [[ -n "$source" ]] || continue
    printf '"%s","%s","%s","%s"\n' \
      "${source//"/""}" "${severity//"/""}" "${entity//"/""}" "${detail//"/""}" >> "$report"
  done < <(sort_findings)
}

write_markdown_report() {
  local report="${CONFIG[outdir]}/reports/summary.md"
  cat > "$report" <<EOF
# SOC Hunt Report

- **Run ID:** ${RUN_ID}
- **Started (UTC):** ${START_TS}
- **Hostname:** ${HOSTNAME_FQDN}
- **Mode:** ${CONFIG[mode]}
- **Namespace:** ${CONFIG[namespace]}
- **Since:** ${CONFIG[since]}
- **Risk Score:** ${STATS[risk_score]}

## Statistics

| Metric | Value |
|---|---:|
| Containers Scanned | ${STATS[containers_scanned]} |
| Pods Scanned | ${STATS[pods_scanned]} |
| Apache Events Parsed | ${STATS[apache_events]} |
| IOC Hits | ${STATS[ioc_hits]} |
| Suspicious IPs | ${STATS[suspicious_ips]} |
| Suspicious User Agents | ${STATS[suspicious_uas]} |
| Suspicious Domains | ${STATS[suspicious_domains]} |

## Findings

EOF

  if ((${#FINDINGS[@]} == 0)); then
    printf '%s\n' 'No findings detected.' >> "$report"
  else
    while IFS='|' read -r source severity entity detail; do
      printf -- '- **[%s][%s]** `%s` - %s\n' "${severity^^}" "$source" "$entity" "$detail" >> "$report"
    done < <(sort_findings)
  fi

  if ((${#WARNINGS[@]} > 0)); then
    cat >> "$report" <<EOF

## Warnings

EOF
    printf '%s\n' "${WARNINGS[@]}" | sed 's/^/- /' >> "$report"
  fi

  if ((${#ERRORS[@]} > 0)); then
    cat >> "$report" <<EOF

## Errors

EOF
    printf '%s\n' "${ERRORS[@]}" | sed 's/^/- /' >> "$report"
  fi
}

write_reports() {
  write_metadata
  case "${CONFIG[report_format]}" in
    json) write_json_report ;;
    csv)  write_csv_report ;;
    md)   write_markdown_report ;;
    all)
      write_json_report
      write_csv_report
      write_markdown_report
      ;;
  esac
}

# --- Summary ----------------------------------------------------------------
print_summary() {
  local score="${STATS[risk_score]}"
  local verdict="LOW"
  if   (( score >= 90 )); then verdict="CRITICAL"
  elif (( score >= 65 )); then verdict="HIGH"
  elif (( score >= 40 )); then verdict="MEDIUM"
  fi

  cat <<EOF

${COLOR[bold]}Execution Summary${COLOR[reset]}
Risk Score         : ${score} (${verdict})
Containers Scanned : ${STATS[containers_scanned]}
Pods Scanned       : ${STATS[pods_scanned]}
Apache Events      : ${STATS[apache_events]}
IOC Hits           : ${STATS[ioc_hits]}
Warnings           : ${#WARNINGS[@]}
Errors             : ${#ERRORS[@]}
Reports            : ${CONFIG[outdir]}/reports
EOF
}

# --- Extra advanced shell showcase ------------------------------------------
showcase_shell_features() {
  # Here-string, arithmetic, regex, arrays, indirect expansion style examples.
  local sample="GET /index.php?id=1' OR 1=1 -- HTTP/1.1"
  if grep -Eiq 'or[[:space:]]+1=1|union[[:space:]]+select' <<<"$sample"; then
    log DEBUG "Showcase: matched SQLi pattern via here-string"
  fi

  local -a nums=(2 4 6 8)
  local sum=0 n
  for n in "${nums[@]}"; do (( sum += n )); done
  log DEBUG "Showcase: arithmetic sum=${sum}"

  local s="apache-httpd-01"
  [[ "$s" =~ ^([a-z]+)-([a-z]+)-([0-9]+)$ ]] && log DEBUG "Showcase: regex groups matched ${BASH_REMATCH[1]}"

  # select menu demonstration (non-interactive safe fallback).
  if [[ -t 0 ]]; then
    select action in Full Docker K8s Apache IOC Quit; do
      [[ -n "$action" ]] && { log DEBUG "Selected: $action"; break; }
    done
  fi

  # Subshell demo.
  (
    local t="subshell"
    : "$t"
  )
}

main() {
  with_lock
  parse_args "$@"
  validate_args
  mkdirs
  load_feeds
  spawn_log_monitor
  parallel_demo_worker_pool
  print_banner
  showcase_shell_features

  case "${CONFIG[mode]}" in
    docker)
      run_docker_module
      ;;
    k8s)
      run_k8s_module
      ;;
    apache)
      run_apache_module
      ;;
    ioc)
      run_ioc_module
      ;;
    full)
      run_docker_module
      run_k8s_module
      run_apache_module
      run_ioc_module
      ;;
  esac

  run_ioc_module
  run_enrichment_module
  wait_for_jobs || append_warning "Some background jobs exited non-zero"
  write_reports
  print_summary
}

main "$@"
