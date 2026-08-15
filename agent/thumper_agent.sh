#!/bin/sh
# Thumper endpoint agent (Bash/POSIX sh, prototype).
#
# Pure shell so endpoints need NO Python runtime - only `curl` and `openssl`
# (both ubiquitous; macOS/Linux ship them). The server's agent-facing API speaks
# a plain-text protocol (key=value + tab-separated lines) precisely so this agent
# never has to parse JSON.
#
# Lifecycle:
#   1. ENROLL  - register this machine (POST /api/enroll) with the shared enroll
#                token baked into the install command. Saves a per-endpoint token.
#   2. PULL    - GET /api/agent/deployments: this endpoint's OWN instances, one
#                tab-separated record each (id, path, hmac_secret, content URL,
#                callback URL). The HMAC secret lives HERE, never in the bait file.
#   3. PLANT   - fetch each instance's bait content and write it to its path.
#   4. WATCH   - detect reads and POST an HMAC-signed, enriched callback per
#                deployment. A read is the signal.
#
# Root is NOT needed to plant a user-space bait (~/.aws, ~/.config, ~/.ssh) or to
# detect reads — the agent runs as the dev user who owns the file. Root is only
# needed to plant bait in a system path like /etc/ssh.
#
# Read detection:
#   • macOS : FIFO named-pipe bait (unprivileged). The agent serves bait content
#             to any opener; `open(O_WRONLY)` blocks until a reader connects, so
#             every read is a guaranteed, synchronous event. No elevated privileges.
#   • Linux : `inotifywait` IN_ACCESS on the bait files (reliable, unprivileged).
#             inotify reports the event but not the accessing process, so alerts
#             are path-only (no process/pid/user). Needs the inotify-tools package.
#   • else  : st_atime poll fallback. Best-effort only - many systems update atime
#             lazily or not at all, so this can miss reads. Last resort.
#
# Example (the shape an MDM/SSH deploy pushes):
#   sh thumper_agent.sh run \
#       --server http://localhost:8000 --enroll-token dev-enroll-token \
#       --tripwire tw_ab12cd34
#   # (sudo only if planting in a system path like /etc/ssh)

set -eu

DEFAULT_STATE="$HOME/.thumper/agent.json"
AGENT_VERSION="0.1.0"
# macOS background daemons that legitimately touch files (indexing/backup/security).
NOISE_PROCS="sh bash thumper_agent curl mds mds_stores mdworker mdworker_shared mdbulkimport mdflagwriter mdsync fseventsd backupd tccd syspolicyd XProtect XprotectService quicklookd Spotlight mdiagnosticd"
DEBOUNCE_SECS=3
REPLANT_MAX=3   # max re-plant attempts per deployment before giving up (verify pass)
# After a callback is rejected with 401 (server no longer knows this deployment -
# DB reset/redeploy, or the tripwire was deleted), re-enroll to pick up fresh
# credentials. Rate-limited so a persistent 401 can't turn every read into an
# enroll storm.
RESYNC_COOLDOWN=30
LAST_RESYNC=0
# FIFO sensor: bait is a named pipe the agent serves. Probed once against the
# state dir's filesystem; if mkfifo is unavailable there we fall back to the
# (fixed) atime poll. Bait content is cached to BAITCACHE so the per-bait
# serving loop can re-serve it on every read.
FIFO_MODE=0
BAITCACHE=""
REPLANTED=0
mkfifo_works() {  # 0 if mkfifo actually works in the state dir (any platform: FIFO works on Linux/CI too)
    command -v mkfifo >/dev/null 2>&1 || return 1
    _probe="$(dirname "$STATE_FILE")/.fifoprobe.$$"
    if mkfifo "$_probe" 2>/dev/null; then rm -f "$_probe"; unset _probe; return 0; fi
    unset _probe; return 1
}
probe_fifo_mode() {  # AUTO policy: default to FIFO on macOS only (Linux defaults to inotify)
    FIFO_MODE=0
    [ "$(platform)" = "darwin" ] || return 0
    mkfifo_works && FIFO_MODE=1
}
# effective_sensor <i>: which sensor governs THIS bait. Precedence:
#   1. an explicit operator --sensor (fifo|atime) - an intentional override that
#      must win over the server (#164 F2): the operator opted out of/into FIFOs;
#   2. the deployment's OWN sensor when the server sent one (dual-plant pairs);
#   3. the platform default.
# Lets one agent run a FIFO bait and an atime bait side by side.
effective_sensor() {
    case "$SENSOR" in fifo|atime) printf '%s' "$SENSOR"; return 0 ;; esac
    eval "_es=\${dep_sensor_$1:-}"
    [ -n "$_es" ] && { printf '%s' "$_es"; return 0; }
    if [ "$FIFO_MODE" = 1 ]; then printf 'fifo'
    elif [ "$(platform)" = linux ] && command -v inotifywait >/dev/null 2>&1; then printf 'inotify'
    else printf 'atime'; fi
}
has_explicit_sensors() {  # 0 if any deployment carries its own sensor (server is sending pairs)
    _i=1
    while [ "$_i" -le "$DEP_COUNT" ]; do
        eval "_s=\${dep_sensor_$_i:-}"
        [ -n "$_s" ] && return 0
        _i=$((_i + 1))
    done
    return 1
}
cache_path() { printf '%s/%s' "$BAITCACHE" "$1"; }   # cache_path <deployment-id>
TAB=$(printf '\t')

log() { printf '[thumper %s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
err() { printf '[thumper %s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# ── state (key=value lines, NOT json) ────────────────────────────────────────
state_get() {  # state_get <file> <key>
    [ -f "$1" ] || return 0
    sed -n "s/^$2=//p" "$1" | head -n1
}

# ── planted-bait manifest ─────────────────────────────────────────────────────
# A flat list (one absolute path per line) of files THIS agent planted, kept next
# to the state file. It lets plant() distinguish bait it owns (safe to refresh)
# from a pre-existing real credential (never touch) - so the overwrite guard can
# still let us rotate our own bait on later runs.
planted_by_us() {  # planted_by_us <path>  -> 0 if we recorded planting it
    [ -f "${MANIFEST_FILE:-}" ] || return 1
    grep -qxF "$1" "$MANIFEST_FILE"
}
record_planted() {  # record_planted <path>
    [ -n "${MANIFEST_FILE:-}" ] || return 0
    mkdir -p "$(dirname "$MANIFEST_FILE")"
    planted_by_us "$1" || printf '%s\n' "$1" >> "$MANIFEST_FILE"
}
forget_planted() {  # forget_planted <path> - drop a path from the manifest
    [ -f "${MANIFEST_FILE:-}" ] || return 0
    tmp="$MANIFEST_FILE.tmp.$$"
    grep -vxF "$1" "$MANIFEST_FILE" > "$tmp" 2>/dev/null || true  # 1 == now empty
    mv "$tmp" "$MANIFEST_FILE"
}

# ── singleton lock ────────────────────────────────────────────────────────────
# Only one agent per install location (keyed to the state-file dir), so a re-run
# of the install command - MDM re-push, reboot, manual paste - doesn't stack
# duplicate watchers all firing the same read. An atomic `mkdir` is the gate; the
# holder is respected only if its PID is alive AND is a thumper_agent process
# (guards PID reuse after a reboot). A dead/foreign lock is reclaimed, so a
# leftover lock from a SIGKILL / power loss never permanently blocks restart.
LOCK_DIR=""

# Is the current lock held by a live thumper_agent? Sets $oldpid as a side effect.
# The winner does `mkdir` then writes `pid` non-atomically, so a momentarily empty
# pid means "holder still initializing", not "abandoned" - re-read once after a
# short pause before treating the lock as stale (closes the mkdir/pid-write race).
lock_holder_alive() {
    oldpid=$(cat "$LOCK_DIR/pid" 2>/dev/null || true)
    if [ -z "$oldpid" ]; then
        sleep 1
        oldpid=$(cat "$LOCK_DIR/pid" 2>/dev/null || true)
    fi
    [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null \
        && ps -p "$oldpid" -o command= 2>/dev/null | grep -q thumper_agent
}

# Another agent already watches this install location (the singleton). Don't start
# a second watcher - instead register our tripwire(s) with the server so the
# running agent plants them on its next live-sync (#12). Enroll is idempotent
# (same machine_id -> same endpoint + token), so this is safe even for an
# accidental identical re-run.
register_with_running_agent() {
    log "another agent is already running (pid $oldpid); registering tripwires for it"
    [ "$FORCE" = 1 ] || preflight_paths || exit 1
    do_enroll || { err "enroll failed"; exit 1; }
    log "registered; the running agent will plant on its next sync (<=${SYNC_INTERVAL}s)"
    exit 0
}

acquire_singleton() {
    LOCK_DIR="$(dirname "$STATE_FILE")/agent.lock"
    mkdir -p "$(dirname "$LOCK_DIR")"             # ensure the state dir exists
    n=0
    while [ "$n" -lt 3 ]; do
        if mkdir "$LOCK_DIR" 2>/dev/null; then     # atomic: exactly one winner
            printf '%s\n' "$$" > "$LOCK_DIR/pid"
            return 0
        fi
        if lock_holder_alive; then
            register_with_running_agent
        fi
        err "clearing stale lock (holder '${oldpid:-?}' is not a live agent)"
        rm -rf "$LOCK_DIR"
        n=$((n + 1))
        sleep 1
    done
    # Sustained contention: a peer keeps winning the mkdir. Defer to it if it's a
    # live agent rather than killing a legitimately-needed start.
    if lock_holder_alive; then
        register_with_running_agent
    fi
    err "could not acquire singleton lock"; exit 1
}

release_singleton() {  # only remove a lock that is still ours
    [ -n "${LOCK_DIR:-}" ] || return 0
    [ "$(cat "$LOCK_DIR/pid" 2>/dev/null || true)" = "$$" ] && rm -rf "$LOCK_DIR"
    return 0
}

# ── id / platform helpers ────────────────────────────────────────────────────
gen_machine_id() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr 'A-F' 'a-f' | tr -d '-'
    elif [ -r /proc/sys/kernel/random/uuid ]; then
        tr -d '-' < /proc/sys/kernel/random/uuid
    else
        # Last resort: time + pid, hashed.
        printf '%s-%s' "$(date +%s)" "$$" | openssl dgst -sha256 | awk '{print $NF}'
    fi
}

platform() { uname -s | tr 'A-Z' 'a-z'; }   # darwin | linux

# ── target user / path expansion (when running as root for system-path planting) ──
# Resolve the real desktop/dev user so bait lands in THEIR home and is owned by
# them (the threat reads as that user), not /var/root.
TARGET_USER=""
TARGET_HOME=""
resolve_target_user() {
    [ "$(id -u)" = "0" ] || return 0          # not root: plant as ourselves
    name="${SUDO_USER:-}"
    if [ -z "$name" ] && [ "$(platform)" = "darwin" ]; then
        name=$(stat -f "%Su" /dev/console 2>/dev/null || true)
    fi
    if [ -n "$name" ] && [ "$name" != "root" ]; then
        TARGET_USER="$name"
        TARGET_HOME=$(eval echo "~$name")
    fi
}

expand_path() {  # expand leading ~ to the right home
    case "$1" in
        "~"/*|"~")
            if [ -n "$TARGET_HOME" ]; then printf '%s%s' "$TARGET_HOME" "${1#\~}"
            else printf '%s%s' "$HOME" "${1#\~}"; fi ;;
        *) printf '%s' "$1" ;;
    esac
}

# ── HTTP + HMAC ───────────────────────────────────────────────────────────────
hmac_sha256() {  # hmac_sha256 <secret> <body>  -> sha256=<hex>
    hex=$(printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" | awk '{print $NF}')
    printf 'sha256=%s' "$hex"
}

# ── lifecycle ─────────────────────────────────────────────────────────────────
do_enroll() {
    machine_id=$(state_get "$STATE_FILE" machine_id)
    [ -n "$machine_id" ] || machine_id=$(gen_machine_id)
    existing_token=$(state_get "$STATE_FILE" agent_token)

    _enroll_extra=""
    [ "$EPHEMERAL" = 1 ] && _enroll_extra="--data-urlencode ephemeral=1"
    # shellcheck disable=SC2086
    resp=$(curl -fsS -X POST "$SERVER/api/enroll" \
        --data-urlencode "enroll_token=$ENROLL_TOKEN" \
        --data-urlencode "hostname=$(hostname)" \
        --data-urlencode "machine_id=$machine_id" \
        --data-urlencode "platform=$(platform)" \
        --data-urlencode "tripwire_ids=$TRIPWIRES" \
        --data-urlencode "agent_token=$existing_token" \
        $_enroll_extra) || {
        err "enroll failed"; return 1; }

    AGENT_TOKEN=$(printf '%s\n' "$resp" | sed -n 's/^agent_token=//p' | head -n1)
    ENDPOINT_ID=$(printf '%s\n' "$resp" | sed -n 's/^endpoint_id=//p' | head -n1)
    [ -n "$AGENT_TOKEN" ] || { err "enroll: no agent_token in response"; return 1; }

    mkdir -p "$(dirname "$STATE_FILE")"
    {
        printf 'machine_id=%s\n' "$machine_id"
        printf 'agent_token=%s\n' "$AGENT_TOKEN"
        printf 'endpoint_id=%s\n' "$ENDPOINT_ID"
    } > "$STATE_FILE"
    log "enrolled as $ENDPOINT_ID"
}

# Pull deployments into indexed vars dep_<field>_<i>; sets DEP_COUNT.
pull_deployments() {
    body=$(curl -fsS "$SERVER/api/agent/deployments" \
        -H "Authorization: Bearer $AGENT_TOKEN") || { err "pull failed"; return 1; }
    DEP_COUNT=0
    oldifs=$IFS
    IFS="$TAB"
    # `printf | while` would subshell the counters away; feed via a here-doc.
    while IFS="$TAB" read -r id path secret content_url callback_url sensor; do
        [ -n "$id" ] || continue
        DEP_COUNT=$((DEP_COUNT + 1))
        eval "dep_id_$DEP_COUNT=\$id"
        eval "dep_path_$DEP_COUNT=\$(expand_path \"\$path\")"
        eval "dep_secret_$DEP_COUNT=\$secret"
        eval "dep_content_$DEP_COUNT=\$content_url"
        eval "dep_callback_$DEP_COUNT=\$callback_url"
        eval "dep_sensor_$DEP_COUNT=\${sensor:-}"   # per-deployment sensor (fifo|atime|inotify); empty = use global default
        eval "dep_last_$DEP_COUNT=0"
    done <<EOF
$body
EOF
    IFS=$oldifs
}

# Fetch this install's bait paths from the server WITHOUT enrolling, then abort
# the whole install if any path is already occupied by a file we didn't plant.
# Fail closed: a path conflict (issue #29) - or an unreachable/uncooperative
# server - refuses the install rather than risk clobbering a real credential.
# Returns 0 only when every path is clear (safe to enroll + plant).
preflight_paths() {
    paths=$(curl -fsS -X POST "$SERVER/api/agent/tripwire-paths" \
        --data-urlencode "enroll_token=$ENROLL_TOKEN" \
        --data-urlencode "tripwire_ids=$TRIPWIRES") || {
        err "preflight: could not fetch tripwire paths from server - not enrolling"; return 1; }

    conflicts=""
    # here-doc (not a pipe) so the conflicts var survives the loop's subshell.
    while IFS= read -r raw; do
        [ -n "$raw" ] || continue
        p=$(expand_path "$raw")
        if { [ -e "$p" ] || [ -L "$p" ]; } && ! planted_by_us "$p"; then
            conflicts="$conflicts$p
"
        fi
    done <<EOF
$paths
EOF

    [ -n "$conflicts" ] || return 0
    err "aborting install: a file we did not plant already exists at:"
    printf '%s' "$conflicts" | while IFS= read -r c; do err "    $c"; done
    err "nothing was planted, no endpoint was enrolled, and the agent is not running."
    err "move/remove the file(s), change the tripwire path(s), or re-run with --force to overwrite."
    return 1
}

report_plant() {            # report_plant <deployment_id> <state>
    curl -fsS -X POST "$SERVER/api/agent/deployments/$1/state" \
        -H "Authorization: Bearer $AGENT_TOKEN" \
        --data-urlencode "state=$2" >/dev/null 2>&1 || log "state report failed: $1"
}

plant() {  # plant <i>
    eval "id=\$dep_id_$1 path=\$dep_path_$1 url=\$dep_content_$1"
    # Defense-in-depth: never act on a traversal path from the server. The server
    # validates on tripwire creation, but the agent runs as root, so don't trust
    # a `..` path even from an authenticated-but-compromised control plane.
    case "/$path/" in
        */../*) err "refusing bait path with '..': $path - skipping $id"; report_plant "$id" failed; return 1 ;;
    esac
    parent=$(dirname "$path")
    [ -z "$parent" ] || mkdir -p "$parent"

    # NEVER clobber a file we didn't plant. At a realistic bait path
    # (~/.aws/credentials, ~/.ssh/id_rsa, …) a pre-existing file is almost
    # certainly a REAL secret, and `curl -o` would truncate it - silent data
    # loss. -e follows symlinks; -L also catches a symlink itself (curl -o would
    # write THROUGH it and trash the link target). --force opts out, for
    # dedicated honeypot boxes with no real creds.
    if { [ -e "$path" ] || [ -L "$path" ]; } && ! planted_by_us "$path" && [ "$FORCE" != 1 ]; then
        err "refusing to overwrite existing $path (not planted by thumper) - skipping $id; pass --force to override"
        report_plant "$id" failed
        return 1
    fi

    # Never write THROUGH a symlink. The guard above only covers links we didn't
    # plant; if a path we DID plant was later swapped for a symlink, `curl -o`
    # would follow it and clobber the link target. We always plant a regular file,
    # so a symlink here is an attack - refuse unconditionally, even under --force.
    if [ -L "$path" ]; then
        err "refusing to write through symlink at $path - skipping $id"
        report_plant "$id" failed
        return 1
    fi

    if [ "$(effective_sensor "$1")" = fifo ]; then
        mkdir -p "$BAITCACHE"
        chmod 700 "$BAITCACHE" 2>/dev/null || true
        cf=$(cache_path "$id")
        if ! curl -fsS "$url" -H "Authorization: Bearer $AGENT_TOKEN" -o "$cf"; then
            rm -f "$cf"; err "failed to fetch bait for $id"; report_plant "$id" failed; return 1
        fi
        chmod 600 "$cf" 2>/dev/null || true
        { [ -p "$path" ] || [ -f "$path" ]; } && rm -f "$path"  # replace our own stale bait on re-plant
        # Record BEFORE mkfifo, not after: a clean-exit signal (INT/TERM) landing
        # in the gap between creating the FIFO and recording it would otherwise
        # leave the FIFO behind, because the teardown trap's remove_fifos only
        # removes paths listed in the manifest. record_planted is idempotent;
        # undo it if mkfifo fails so the manifest never lists a phantom path.
        record_planted "$path"
        if ! mkfifo "$path" 2>/dev/null; then
            forget_planted "$path"; rm -f "$cf"; err "mkfifo failed at $path - skipping $id"; report_plant "$id" failed; return 1
        fi
        chmod 600 "$path" 2>/dev/null || true
        [ -n "$TARGET_USER" ] && chown "$TARGET_USER" "$path" 2>/dev/null || true
        report_plant "$id" planted
        log "planted (fifo) $id -> $path"
        return 0
    fi

    # Planting a REGULAR-file bait: if a leftover FIFO sits at this path (e.g. a
    # prior FIFO run, swept-miss), remove it first - `curl -o` into a no-reader
    # FIFO blocks forever (Roee #160 F1). Only our own bait reaches here (the
    # overwrite guard above already refused a path we didn't plant).
    [ -p "$path" ] && rm -f "$path"
    if ! curl -fsS "$url" -H "Authorization: Bearer $AGENT_TOKEN" -o "$path"; then
        rm -f "$path"   # remove the partial/empty file curl may have left
        err "failed to fetch bait for $id"
        report_plant "$id" failed
        return 1
    fi
    record_planted "$path"
    chmod 600 "$path" 2>/dev/null || true
    if [ -n "$TARGET_USER" ]; then
        chown "$TARGET_USER" "$path" 2>/dev/null || true
    fi
    report_plant "$id" planted
    log "planted $id -> $path"
}

# Re-enroll + re-pull to recover credentials after the server stops recognizing
# this endpoint's deployments (DB reset/redeploy, endpoint deleted, …). Rate-
# limited via LAST_RESYNC so a persistent 401 can't become an enroll storm.
# Returns 0 if a fresh enroll+pull actually ran, 1 otherwise (cooldown or failure).
resync() {
    now=$(date +%s)
    if [ "$LAST_RESYNC" -ne 0 ] && [ $((now - LAST_RESYNC)) -lt "$RESYNC_COOLDOWN" ]; then
        log "resync skipped (cooldown: $((RESYNC_COOLDOWN - (now - LAST_RESYNC)))s remaining)"
        return 1
    fi
    LAST_RESYNC=$now
    log "callback rejected (401) - re-enrolling to refresh credentials"
    do_enroll || { err "re-enroll failed"; return 1; }
    pull_deployments || { err "re-pull after re-enroll failed"; return 1; }
    return 0
}

fire() {  # fire <i> <event_type> <process> <pid> <os_user> <accessed_path>
    FIRE_RETRIED=0
    [ "${EPHEMERAL:-0}" = "1" ] && touch "$(dirname "$STATE_FILE")/triggered" 2>/dev/null || true
    _fire "$@"
}

# Single-attempt POST. On 401 (deployment unknown to the server) it re-enrolls
# once, relocates this path's NEW deployment index, and replays the SAME event so
# the read that triggered us still alerts under fresh credentials.
_fire() {
    eval "id=\$dep_id_$1 secret=\$dep_secret_$1 callback=\$dep_callback_$1 path=\$dep_path_$1"
    event_type=$2; process=$3; pid=$4; os_user=$5; accessed_path=${6:-$path}
    summary=${process:-unknown}
    [ -n "$pid" ] && summary="$summary (pid $pid)"
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    body=$(printf 'deployment_id=%s\nevent_type=%s\nprocess=%s\npid=%s\nos_user=%s\naccessed_path=%s\ntriggered_by=%s\ntimestamp=%s' \
        "$id" "$event_type" "$process" "$pid" "$os_user" "$accessed_path" "$summary" "$ts")
    sig=$(hmac_sha256 "$secret" "$body")
    # No -f: we want to read the HTTP status (401) instead of just a curl failure.
    code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$callback" \
        -H "X-Thumper-Signature: $sig" --data-binary "$body" 2>/dev/null) || code=000
    case "$code" in
        2??) log "callback ($summary)" ;;
        401)
            if [ "$FIRE_RETRIED" = "0" ] && resync; then
                FIRE_RETRIED=1
                # NOTE: recovers a rotated deployment id/secret for an EXISTING
                # tripwire+path. After resync, dep_index_for_line re-matches the
                # path against the refreshed deployment set.
                new_idx=$(dep_index_for_line "$accessed_path") || {
                    err "callback REJECTED - path not deployed after re-enroll ($summary)"; return 0; }
                _fire "$new_idx" "$event_type" "$process" "$pid" "$os_user" "$accessed_path"
            else
                err "callback REJECTED (401) ($summary)"
            fi ;;
        *) err "callback failed (HTTP $code) ($summary)" ;;
    esac
}

user_of_pid() { ps -o user= -p "$1" 2>/dev/null | tr -d ' '; }

# ── heartbeat (liveness signal to the server) ────────────────────────────────
# Read the token from the state file each beat (not the fork-time copy): the main
# process owns re-enrollment (resync rewrites the state file), so the heartbeat
# transparently picks up a refreshed token without enrolling itself.
heartbeat_loop() {
    while true; do
        sleep "$HEARTBEAT"
        tok=$(state_get "$STATE_FILE" agent_token)
        # Capture the body: the server answers "decommission" (instead of "ok")
        # to tell this agent to self-destruct. Signal the main process to do the
        # teardown - it owns the watcher, lock, and traps.
        resp=$(curl -fsS -X POST "$SERVER/api/agent/heartbeat" \
            -H "Authorization: Bearer $tok" 2>/dev/null) || { log "heartbeat failed"; continue; }
        if [ "$resp" = "decommission" ]; then
            log "decommission signal received from server"
            kill -USR1 "$MAIN_PID" 2>/dev/null
            return
        fi
        log "heartbeat succeeded"
    done
}

# Remove every bait this agent planted (from its manifest). Used by self-destruct.
unplant_all() {
    [ -f "${MANIFEST_FILE:-}" ] || return 0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        rm -f "$p" && log "removed bait $p"
    done < "$MANIFEST_FILE"
}

# Full self-destruct: stop watching, unplant all bait, confirm to the server so it
# drops our record, release the lock, and delete our own install dir + state. Runs
# in the main process via a USR1 trap so it can reach the watcher PID and lock.
self_destruct() {
    trap - EXIT INT TERM USR1     # we own teardown from here
    log "self-destructing: unplanting all bait and removing agent"
    stop_watcher 2>/dev/null
    [ -n "${HEARTBEAT_PID:-}" ] && kill "$HEARTBEAT_PID" 2>/dev/null
    unplant_all
    tok=$(state_get "$STATE_FILE" agent_token)
    curl -fsS -X POST "$SERVER/api/agent/decommissioned" \
        -H "Authorization: Bearer $tok" >/dev/null 2>&1 || log "decommission confirm failed"
    release_singleton              # removes the agent.lock/ dir if it's ours
    dir=$(dirname "$STATE_FILE")
    # Remove only the files we created, then rmdir. No `rm -rf` on a derived path:
    # rmdir is non-recursive and refuses a non-empty dir, so a misconfigured
    # --state-file can never wipe '/', $HOME, or anything we didn't plant here.
    rm -rf "$BAITCACHE" 2>/dev/null || true   # fake creds must not linger after decommission
    rm -f "$STATE_FILE" "$MANIFEST_FILE" "$dir/agent.log" "$dir/thumper_agent.sh"
    rmdir "$dir" 2>/dev/null || log "left $dir in place (not empty)"
    log "agent removed"
    exit 0
}

dep_index_for_line() {  # echo the deployment index whose path appears in the line
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        eval "p=\$dep_path_$i"
        case "$1" in *"$p"*) printf '%s' "$i"; return 0 ;; esac
        i=$((i + 1))
    done
    return 1
}

is_noise()   { for n in $NOISE_PROCS; do [ "$n" = "$1" ] && return 0; done; return 1; }

watch_inotify() {
    # Linux read sensor: inotify IN_ACCESS fires on read. `%w` is the watched
    # path. inotify gives no accessing process, so process/pid/user are empty
    # (path-only alerts, handled like the atime fallback). Works unprivileged.
    command -v inotifywait >/dev/null 2>&1 || return 1
    set --
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        eval "p=\$dep_path_$i"
        set -- "$@" "$p"
        i=$((i + 1))
    done
    log "watching $DEP_COUNT bait file(s) via inotify (path-only; no process/user)"
    # Do NOT swallow inotifywait's stderr: if it can't start, or dies at runtime
    # (e.g. fs.inotify.max_user_watches exhaustion), we want that in the log. A
    # silently-dark sensor looks exactly like "no one touched the bait", which is
    # the worst possible failure for a tripwire. -q already keeps normal startup
    # quiet, so only real errors reach the log here.
    mark_ready   # inotify -m begins monitoring immediately; signal steady state
    inotifywait -m -q -e access --format '%w' -- "$@" | while read -r path; do
        idx=""
        j=1
        while [ "$j" -le "$DEP_COUNT" ]; do
            eval "wp=\$dep_path_$j"
            [ "$wp" = "$path" ] && { idx=$j; break; }
            j=$((j + 1))
        done
        [ -n "$idx" ] || continue
        now=$(date +%s)
        eval "last=\$dep_last_$idx"
        [ $((now - last)) -lt "$DEBOUNCE_SECS" ] && continue
        eval "dep_last_$idx=\$now"
        fire "$idx" "access" "" "" "" "$path"
    done
    # Reached only when inotifywait exited on its own. If the stop was deliberate
    # (reconcile/shutdown set the flag), stay quiet - stop_watcher is tearing this
    # subshell down anyway. Otherwise the real sensor just died: say so loudly and
    # degrade to the atime poll so we keep *some* coverage rather than going blind.
    [ -e "${WATCH_STOP_FLAG:-/nonexistent}" ] && return 0
    err "inotify watcher exited unexpectedly - degrading to atime poll"
    watch_atime
}

# atime sensor helpers. Detection-only (no process/user) but works on a NORMAL
# regular-file bait under all constraints (no kdebug, no mount, no privilege),
# so it's the primary layer that covers the FIFO sensor's blind spots
# (statSync-guarded / mmap / scan-only readers). See #28, #100.
ATIME_ARM_STAMP=200001010000   # `touch -t` stamp: 2000-01-01 00:00 - atime far in the past
arm_atime() {  # arm_atime <path>: set atime to the past so the next read bumps it (relatime/APFS)
    # -c: never CREATE the file. Arming a missing bait would otherwise leave an
    # empty file behind, making verify_planted think a failed-plant dep is planted
    # and silently skip re-planting it (#28/#100).
    touch -a -c -t "$ATIME_ARM_STAMP" "$1" 2>/dev/null || true
}
read_atime() {  # read_atime <path>: portable access-time epoch (GNU %X first, then BSD %a - never %a on Linux, that's free blocks: #28)
    stat -c %X "$1" 2>/dev/null || stat -f %a "$1" 2>/dev/null || echo 0
}
all_indices() {  # "1 2 ... DEP_COUNT" - every deployment
    _ai=""; _i=1
    while [ "$_i" -le "$DEP_COUNT" ]; do _ai="$_ai $_i"; _i=$((_i + 1)); done
    printf '%s' "$_ai"
}
# atime_poll "<idx idx ...>": arm + re-armable-poll only the given deployments.
# The index list lets the mixed watcher poll just the atime baits while FIFO
# baits are served separately; watch_atime() polls all (homogeneous + fallback).
atime_poll() {
    log "atime poll every ${POLL}s on regular-file bait(s) (re-armable; detection only - no process/user)"
    # shellcheck disable=SC2086  # $1 is a space-separated index list; splitting is intended
    for i in $1; do
        eval "p=\$dep_path_$i"
        arm_atime "$p"                                  # arm so relatime bumps atime on a read
        eval "atime_$i=\$(read_atime \"\$p\")"
    done
    mark_armed   # gen 1: initial baselines captured - reads are now detectable
    mark_ready   # atime watcher is at steady state
    while true; do
        sleep "$POLL"
        # shellcheck disable=SC2086
        for i in $1; do
            eval "p=\$dep_path_$i prev=\$atime_$i"
            cur=$(read_atime "$p")
            if [ "$cur" != "0" ] && [ "$cur" -gt "$prev" ] 2>/dev/null; then
                fire "$i" "atime-change" "" "" "" "$p"
                arm_atime "$p"                          # RE-ARM so the NEXT read is detectable too
                eval "atime_$i=\$(read_atime \"\$p\")"
                mark_armed   # gen++: this bait re-armed + re-baselined
            fi
        done
    done
}
watch_atime() { atime_poll "$(all_indices)"; }   # poll every bait (homogeneous atime mode + degradation fallback)

# ── live sync (re-pull + reconcile) ───────────────────────────────────────────
# A running agent re-pulls its deployment set every --sync-interval and applies
# the diff (plant added, remove dropped) WITHOUT a restart, so a tripwire added
# to or removed from this endpoint takes effect on a live box. The watcher is
# restarted ONLY when the set actually changed - never periodically - so we never
# blind ourselves between cycles.
WATCH_PID=""
WATCH_STARTED=""

# Steady-state signal (#237): a watcher writes WATCH_READY_FILE and logs once it
# is fully up - workers spawned AND (for atime) baselines captured. Tests wait on
# this instead of racing the sub-second startup window with weak "armed?" gates.
# Idempotent: a re-armed/reconciled watcher simply re-touches it.
mark_ready() {
    : > "${WATCH_READY_FILE:-/dev/null}" 2>/dev/null || true
    log "watcher ready"
}

# atime-only: an "armed generation" bumped after EACH baseline (re)capture, so a
# test can wait past a specific re-arm before simulating the next read (the
# arm->baseline window is otherwise a race - see #235). One writer (the atime
# poll subshell), so the plain counter is safe.
mark_armed() {
    ATIME_ARMED_GEN=$(( ${ATIME_ARMED_GEN:-0} + 1 ))
    printf '%s' "$ATIME_ARMED_GEN" > "${ATIME_ARMED_FILE:-/dev/null}" 2>/dev/null || true
}

# Record sensor workers owned by the current supervisor. If that supervisor is
# killed abruptly, its children are reparented and `pkill -P` can no longer find
# them; this registry lets the sync loop remove those orphans before restart.
process_start_fingerprint() {  # stable for one PID lifetime; empty if gone
    # BSD `lstart` is second-resolution, so include the full command as an
    # additional identity dimension while keeping this agent shell-only.
    # NOTE: our workers are backgrounded shell FUNCTIONS (serve_fifo/atime_poll),
    # so `command=` is the agent's own argv for every one of them - it hardens the
    # fingerprint against a foreign process that reused the PID, but does NOT tell
    # two same-second siblings of THIS agent apart. The `_ww_owner = MAIN_PID`
    # gate in cleanup_watcher_workers is what bounds a kill to this agent's own
    # workers; the fingerprint only guards against acting on a reused PID.
    ps -o lstart=,command= -p "$1" 2>/dev/null |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

process_identity_matches() {  # process_identity_matches <pid> <fingerprint>
    [ -n "${1:-}" ] && [ -n "${2:-}" ] || return 1
    _identity_current=$(process_start_fingerprint "$1")
    [ -n "$_identity_current" ] && [ "$_identity_current" = "$2" ]
}

watcher_identity_matches() {
    [ -n "${WATCH_PID:-}" ] && [ -n "${WATCH_STARTED:-}" ] || return 1
    process_identity_matches "$WATCH_PID" "$WATCH_STARTED"
}

write_watcher_workers() {  # write_watcher_workers <pid ...>
    [ -n "${WATCH_WORKERS_FILE:-}" ] || return 0
    _ww_tmp="$WATCH_WORKERS_FILE.tmp.$$"
    : > "$_ww_tmp"
    for _ww_pid in "$@"; do
        [ -n "$_ww_pid" ] || continue
        _ww_started=$(process_start_fingerprint "$_ww_pid")
        [ -n "$_ww_started" ] && printf '%s\t%s\t%s\n' \
            "$MAIN_PID" "$_ww_pid" "$_ww_started" >> "$_ww_tmp"
    done
    mv "$_ww_tmp" "$WATCH_WORKERS_FILE"
}

cleanup_watcher_workers() {
    [ -f "${WATCH_WORKERS_FILE:-}" ] || return 0
    _ww_tab=$(printf '\t')
    while IFS="$_ww_tab" read -r _ww_owner _ww_pid _ww_started; do
        case "$_ww_owner:$_ww_pid" in *[!0-9:]*|:|*:) continue ;; esac
        [ "$_ww_owner" = "$MAIN_PID" ] || continue
        # A bare PID is unsafe: the worker may have exited and its PID may have
        # been reused during the sync interval. Kill only the exact process
        # lifetime recorded by this main agent instance.
        process_identity_matches "$_ww_pid" "$_ww_started" &&
            kill "$_ww_pid" 2>/dev/null || true
    done < "$WATCH_WORKERS_FILE"
    rm -f "$WATCH_WORKERS_FILE"
}

snapshot() {  # emit the current set as "id<TAB>path" lines
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        eval "printf '%s\t%s\n' \"\$dep_id_$i\" \"\$dep_path_$i\""
        i=$((i + 1))
    done
}

plant_all() {  # plant every current deployment; sets `planted`
    planted=0
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        if plant "$i"; then planted=$((planted + 1)); fi
        i=$((i + 1))
    done
}

# attribute <fifo> : best-effort set globals pid/process/os_user to the reader's.
# lsof <path> does NOT report FIFO openers on macOS; full-scan and match by inode.
attribute() {  # attribute <fifo> ; best-effort set globals pid/process/os_user
    pid=""; process=""; os_user=""
    command -v lsof >/dev/null 2>&1 || return 0
    ino=$(stat -f %i "$1" 2>/dev/null || stat -c %i "$1" 2>/dev/null) || return 0
    [ -n "$ino" ] || return 0
    # Full scan: pick the process whose fd on THIS inode is open for READ (4r) and
    # is not our serve subshell ($$). Inode matched as a standalone field so a
    # blank DEVICE column can't shift parsing.
    pid=$(lsof -nP 2>/dev/null | awk -v ino="$ino" -v me="$$" '
        index($0,"FIFO") && $2!=me && $4 ~ /r$/ && $0 ~ ("(^|[[:space:]])" ino "([[:space:]]|$)") { print $2; exit }')
    [ -n "$pid" ] || { pid=""; return 0; }
    process=$(ps -o comm= -p "$pid" 2>/dev/null | sed 's#.*/##' | tr -d ' ')
    os_user=$(user_of_pid "$pid")
}

serve_fifo() {  # serve_fifo <i> - serve one bait FIFO forever; a read = a hit
    eval "fifo=\$dep_path_$1 id=\$dep_id_$1"
    cf=$(cache_path "$id")
    trap '' PIPE                                    # a reader closing early must not kill us
    while [ -p "$fifo" ]; do
        exec 3>"$fifo" || break                     # open(O_WRONLY) BLOCKS until a reader opens
        attribute "$fifo"                           # reader is parked in read(); grab it before we write
        cat "$cf" >&3 2>/dev/null || true           # serve bait into the held fd (ignore EPIPE)
        exec 3>&-                                    # close -> reader gets EOF
        now=$(date +%s); eval "last=\${dep_last_$1:-0}"
        if [ $((now - last)) -ge "$DEBOUNCE_SECS" ]; then
            eval "dep_last_$1=\$now"
            is_noise "$process" || fire "$1" open "$process" "$pid" "$os_user" "$fifo"
        fi
    done
}

watch_fifo() {  # supervisor: keep one serve_fifo alive per bait; restart any that dies
    log "watching $DEP_COUNT bait file(s) via FIFO"
    update_fifo_worker_registry() {
        _worker_pids=""; _wr_i=1
        while [ "$_wr_i" -le "$DEP_COUNT" ]; do
            eval "_wr_pid=\$sf_pid_$_wr_i"
            _worker_pids="$_worker_pids $_wr_pid"
            _wr_i=$((_wr_i + 1))
        done
        # shellcheck disable=SC2086
        write_watcher_workers $_worker_pids
    }
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        serve_fifo "$i" &
        eval "sf_pid_$i=\$! sf_started_$i=\$(process_start_fingerprint \"\$!\")"
        i=$((i + 1))
    done
    update_fifo_worker_registry
    mark_ready   # all FIFO writers spawned - steady state
    while :; do
        [ -e "${WATCH_STOP_FLAG:-/nonexistent}" ] && return 0
        i=1
        while [ "$i" -le "$DEP_COUNT" ]; do
            eval "_sp=\$sf_pid_$i _ss=\$sf_started_$i _sf=\$dep_path_$i"
            # Restart a writer that died while its FIFO still exists. Without this
            # that ONE bait has no writer, any reader's open() blocks forever, and
            # nothing fires - and verify_planted can't catch it because it only
            # checks FIFO existence, not writer liveness (Roee #123 F3 residual).
            # A bare `wait` can't do per-writer recovery: it blocks until ALL
            # writers exit, so a single death among live siblings went unrecovered
            # until the next full re-plant restart. And we must NOT fall back to
            # atime: atime polling on a writerless pipe is silently blind.
            if [ -p "$_sf" ] && ! process_identity_matches "$_sp" "$_ss"; then
                # A deliberate stop sets WATCH_STOP_FLAG *before* it pkill's the
                # writers, so re-check it here: a writer that just died because
                # we're shutting down must NOT be respawned. Without this guard a
                # respawn in stop_watcher's pkill->kill window leaks a serve_fifo
                # blocked in open(O_WRONLY) (no reader); that orphan keeps the
                # agent's stdout/stderr open, so on SIGTERM the process never
                # reaches EOF and shutdown intermittently hangs.
                [ -e "${WATCH_STOP_FLAG:-/nonexistent}" ] && return 0
                serve_fifo "$i" &
                eval "sf_pid_$i=\$! sf_started_$i=\$(process_start_fingerprint \"\$!\")"
                update_fifo_worker_registry
                log "restarted dead FIFO writer for bait $i"
            fi
            i=$((i + 1))
        done
        sleep 1
    done
}

# Dual-plant: each deployment runs under its OWN sensor. FIFO baits (canonical,
# definitive pid) are served individually; atime/inotify baits (companion,
# detection) are atime-polled as a group. Used whenever the server sends pairs.
watch_mixed() {
    log "watching $DEP_COUNT bait(s) with per-deployment sensors"
    _atidx=""; i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        if [ "$(effective_sensor "$i")" = fifo ]; then
            serve_fifo "$i" &
            eval "sf_pid_$i=\$! sf_started_$i=\$(process_start_fingerprint \"\$!\")"
        else
            _atidx="$_atidx $i"                         # atime/inotify/unknown -> atime poll (detection)
        fi
        i=$((i + 1))
    done
    _atime_pid=""
    if [ -n "$_atidx" ]; then
        atime_poll "$_atidx" &
        _atime_pid=$!
        _atime_started=$(process_start_fingerprint "$_atime_pid")
    fi
    update_mixed_worker_registry() {
        _worker_pids=""; _wr_i=1
        while [ "$_wr_i" -le "$DEP_COUNT" ]; do
            if [ "$(effective_sensor "$_wr_i")" = fifo ]; then
                eval "_wr_pid=\$sf_pid_$_wr_i"
                _worker_pids="$_worker_pids $_wr_pid"
            fi
            _wr_i=$((_wr_i + 1))
        done
        [ -n "$_atidx" ] && _worker_pids="$_worker_pids $_atime_pid"
        # shellcheck disable=SC2086
        write_watcher_workers $_worker_pids
    }
    update_mixed_worker_registry
    # Steady state (#237): with atime companions, the backgrounded atime_poll marks
    # ready after IT captures baselines (the last thing to come up, since the FIFO
    # writers spawned above). With no atime baits, nothing else will - so mark here.
    [ -z "$_atidx" ] && mark_ready
    # Supervise the FIFO writers, exactly like watch_fifo: a serve_fifo that dies
    # leaves its pipe on disk, so any reader's open() blocks forever and that bait
    # is silently blind until a full restart (Roee #160 N1). Re-check the stop flag
    # before every (re)spawn so a deliberate teardown can't leak a writer that
    # would hold the agent's stdout/stderr open on shutdown.
    while :; do
        [ -e "${WATCH_STOP_FLAG:-/nonexistent}" ] && return 0
        # The mixed supervisor itself can stay alive after its atime child dies.
        # Track that child explicitly so top-level WATCH_PID liveness cannot hide
        # a partially blind sensor set (#99, follow-up from #160).
        if [ -n "$_atidx" ] && ! process_identity_matches "$_atime_pid" "$_atime_started"; then
            [ -e "${WATCH_STOP_FLAG:-/nonexistent}" ] && return 0
            atime_poll "$_atidx" &
            _atime_pid=$!
            _atime_started=$(process_start_fingerprint "$_atime_pid")
            update_mixed_worker_registry
            log "restarted dead atime watcher"
        fi
        i=1
        while [ "$i" -le "$DEP_COUNT" ]; do
            if [ "$(effective_sensor "$i")" = fifo ]; then
                eval "_sp=\$sf_pid_$i _ss=\$sf_started_$i _sf=\$dep_path_$i"
                if [ -p "$_sf" ] && ! process_identity_matches "$_sp" "$_ss"; then
                    [ -e "${WATCH_STOP_FLAG:-/nonexistent}" ] && return 0
                    serve_fifo "$i" &
                    eval "sf_pid_$i=\$! sf_started_$i=\$(process_start_fingerprint \"\$!\")"
                    update_mixed_worker_registry
                    log "restarted dead FIFO writer for bait $i"
                fi
            fi
            i=$((i + 1))
        done
        sleep 1
    done
}

start_watcher() {  # launch the right sensor in the background; set WATCH_PID
    rm -f "${WATCH_STOP_FLAG:-}" 2>/dev/null || true   # this start is not a stop
    # An explicit operator --sensor wins over server-sent per-deployment sensors:
    # effective_sensor already plants EVERY bait per the override, so route to the
    # matching single-sensor watcher. Checking --sensor before has_explicit_sensors
    # keeps a forced-FIFO run under the SUPERVISED watch_fifo instead of the mixed
    # watcher (Roee #160 N2, the trigger for N1).
    if [ "$SENSOR" = fifo ]; then
        watch_fifo &                                    # operator forced FIFO (supervised)
    elif [ "$SENSOR" = atime ]; then
        watch_atime &                                   # operator forced atime (any platform)
    elif has_explicit_sensors; then
        watch_mixed &                                   # per-deployment sensors (dual-plant pairs)
    elif [ "$FIFO_MODE" = 1 ]; then
        watch_fifo &
    elif [ "$(platform)" = "linux" ] && command -v inotifywait >/dev/null 2>&1; then
        watch_inotify &
    else
        watch_atime &
    fi
    WATCH_PID=$!
    WATCH_STARTED=$(process_start_fingerprint "$WATCH_PID")
    if [ -z "$WATCH_STARTED" ]; then
        # The supervisor exited before its identity could be captured. Leave no
        # unverified PID that a later stop/restart path might signal.
        WATCH_PID=""
    fi
}

stop_watcher() {  # kill the watcher AND its serve_fifo children
    [ -n "${WATCH_PID:-}" ] || return 0
    : > "${WATCH_STOP_FLAG:-/dev/null}" 2>/dev/null || true  # mark stop deliberate
    # Reap children FIRST. Killing the parent subshell first reparents the
    # serve_fifo / inotifywait children to PID 1, after which `pkill -P` matches
    # nothing and leaks them on every reconcile. The registry is the fallback
    # for workers already orphaned by an abrupt supervisor death.
    _old_watcher=$WATCH_PID
    _old_watcher_matches=0
    watcher_identity_matches && _old_watcher_matches=1
    if [ "$_old_watcher_matches" = 1 ]; then
        pkill -P "$_old_watcher" 2>/dev/null || true
        kill "$_old_watcher" 2>/dev/null || true
    fi
    # Do not let start_watcher remove the stop flag until the old supervisor can
    # no longer respawn workers or overwrite the registry for the next generation.
    # `wait` is safe even when identity no longer matches: it addresses only this
    # shell's original child job, never the unrelated process that reused its PID.
    wait "$_old_watcher" 2>/dev/null || true
    cleanup_watcher_workers
    WATCH_PID=""
    WATCH_STARTED=""
}

remove_fifos() {  # remove every manifest path that is a FIFO (clean exit / startup sweep)
    [ -f "${MANIFEST_FILE:-}" ] || return 0
    while IFS= read -r p; do
        [ -n "$p" ] && [ -p "$p" ] && rm -f "$p" && log "removed fifo bait $p"
    done < "$MANIFEST_FILE"
    return 0
}

# reconcile <old-snapshot>: dep_* already hold the NEW set (post re-pull).
reconcile() {
    _old=$1
    _newids=" "
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        eval "_newids=\"\$_newids\$dep_id_$i \""
        i=$((i + 1))
    done
    # Removed: id in old, gone from new → delete the bait WE planted at its path.
    # ONLY if we planted it: an un-assign must never destroy a real credential
    # that happens to sit at that path (mirrors plant()'s overwrite guard). After
    # removing, forget the path so the manifest doesn't keep vouching for it.
    printf '%s\n' "$_old" | while IFS="$TAB" read -r oid opath; do
        [ -n "$oid" ] && [ -n "$opath" ] || continue
        case "$_newids" in
            *" $oid "*) : ;;
            *)
                if planted_by_us "$opath"; then
                    rm -f "$opath" && log "removed bait $oid -> $opath"
                    forget_planted "$opath"
                else
                    err "not removing $opath ($oid) - not planted by thumper"
                fi ;;
        esac
    done
    # Added: id in new, absent from old → plant it.
    _oldids=" $(printf '%s\n' "$_old" | cut -f1 | tr '\n' ' ')"
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        eval "nid=\$dep_id_$i"
        case "$_oldids" in
            *" $nid "*) : ;;
            *) plant "$i" && log "planted new $nid" ;;
        esac
        i=$((i + 1))
    done
}

# Re-stat each current deployment; a missing bait (deleted/tampered, or a plant
# that never landed) is reported failed every cycle and re-planted up to
# REPLANT_MAX times OVER THE AGENT'S LIFETIME (counter keyed by deployment id so
# it survives reconcile reshuffles; never reset - a restart zeroes it). After the
# cap we keep reporting failed but stop re-planting, so a path that keeps failing
# (or an attacker repeatedly deleting bait) can never turn this into a hot loop.
verify_planted() {
    i=1
    while [ "$i" -le "$DEP_COUNT" ]; do
        eval "p=\$dep_path_$i vid=\$dep_id_$i"
        if [ -L "$p" ]; then
            # A symlink where our (regular-file) bait should be is tampering - an
            # attacker could point it at a sensitive file. NEVER treat it as planted
            # and never re-plant through it (curl -o would write the target); report
            # failed so the lost coverage is visible.
            report_plant "$vid" failed
        elif [ "$(effective_sensor "$i")" = fifo ] && [ -e "$p" ] && ! [ -p "$p" ]; then
            # A regular file where our FIFO should be = tampering/replacement.
            # Recover like the "missing" branch below: plant() removes the impostor
            # (our own path) and re-creates the FIFO, then REPLANTED restarts the
            # watcher to serve it. A bare report-failed would leave the sensor
            # permanently blind - while a mere *deletion* self-heals, so a
            # *replacement* must recover too, not be the stronger attack (Roee #123 F1).
            report_plant "$vid" failed
            eval "a=\${heal_$vid:-0}"
            if [ "$a" -lt "$REPLANT_MAX" ]; then
                if plant "$i"; then
                    log "recovered tampered FIFO bait $vid"
                    REPLANTED=1
                else
                    eval "heal_$vid=$((a + 1))"
                    log "FIFO recovery failed for $vid ($((a + 1))/$REPLANT_MAX)"
                fi
            fi
        elif [ -e "$p" ]; then
            # Bait is on disk → re-assert planted every cycle. Recovers a deployment
            # whose initial report was lost (e.g. a network blip during report_plant)
            # instead of leaving it stuck `pending` on the server forever.
            report_plant "$vid" planted
        else
            # Missing → report failed, then re-plant up to REPLANT_MAX times. The
            # counter is bumped ONLY when a plant attempt FAILS, so a transient fetch
            # error (or a successful recovery) doesn't burn the budget permanently.
            report_plant "$vid" failed
            eval "a=\${heal_$vid:-0}"
            if [ "$a" -lt "$REPLANT_MAX" ]; then
                if plant "$i"; then
                    log "re-planted missing bait $vid"
                    # The OLD atime watcher is still polling with a year-2000
                    # baseline until REPLANTED restarts it below; the freshly
                    # fetched file's atime is "now", which it would read as a jump
                    # and fire a ghost alert with no real read. Arm the new bait to
                    # year-2000 so it sees baseline == atime and stays quiet (Roee
                    # #160 F2). Only atime baits are affected; done here (re-plant
                    # only) not in plant(), so the initial-plant baseline capture is
                    # untouched.
                    [ "$(effective_sensor "$i")" = atime ] && arm_atime "$p"
                    REPLANTED=1
                else
                    eval "heal_$vid=$((a + 1))"
                    log "re-plant failed for $vid ($((a + 1))/$REPLANT_MAX)"
                fi
            else
                log "bait missing at $p - giving up after $REPLANT_MAX attempts"
            fi
        fi
        i=$((i + 1))
    done
}

run() {
    STATE_FILE=${STATE_FILE:-$DEFAULT_STATE}
    MANIFEST_FILE="$(dirname "$STATE_FILE")/planted.list"
    BAITCACHE="$(dirname "$STATE_FILE")/bait"
    WATCH_STOP_FLAG="$(dirname "$STATE_FILE")/watcher.stopping"
    WATCH_WORKERS_FILE="$(dirname "$STATE_FILE")/watcher.workers"
    WATCH_READY_FILE="$(dirname "$STATE_FILE")/ready"          # steady-state signal (#237)
    ATIME_ARMED_FILE="$(dirname "$STATE_FILE")/atime_armed"    # atime re-arm generation (#237)
    mkdir -p "$(dirname "$STATE_FILE")"
    case "$SENSOR" in
        atime) FIFO_MODE=0; log "sensor: atime poll (regular-file bait, re-armable)" ;;
        fifo)  # operator forced FIFO: honor it on ANY platform (mkfifo works on Linux/CI), or fail loudly
               if mkfifo_works; then FIFO_MODE=1; log "sensor: FIFO bait (forced)"
               else err "--sensor fifo requested but mkfifo is unavailable here"; exit 1; fi ;;
        *)     probe_fifo_mode
               [ "$FIFO_MODE" = 1 ] && log "sensor: FIFO bait (macOS)" ;;
    esac
    MAIN_PID=$$   # so the backgrounded heartbeat loop can signal us to self-destruct
    # Enforce one-agent-per-install before any work; a duplicate exits here (the
    # EXIT trap below is NOT yet set, so it can't disturb the live holder's lock).
    acquire_singleton
    trap 'release_singleton; exit 0' INT TERM
    trap 'release_singleton' EXIT
    # Only the lock holder sweeps stale FIFOs from a prior hard-kill; a duplicate
    # invocation exits at acquire_singleton above and must never touch the live
    # agent's shared manifest/FIFOs (MDM re-push safety). Sweep regardless of the
    # CURRENT sensor: a prior FIFO run's leftover pipes must be cleared even when
    # this run is atime mode, else plant() would curl into a no-reader FIFO and
    # hang forever (only manifest paths that ARE FIFOs are removed, so it's safe).
    # A worker registry is valid only for the main-process lifecycle that wrote
    # it. Never act on stale PIDs from an earlier boot/run: they may have been
    # reused by an unrelated process. Current-run supervisors recreate the file.
    rm -f "$WATCH_WORKERS_FILE"
    # Clear any steady-state markers from a prior run so a test can't observe a
    # stale "ready"/generation before THIS run's watcher actually comes up (#237).
    rm -f "$WATCH_READY_FILE" "$ATIME_ARMED_FILE"
    remove_fifos
    resolve_target_user

    # Abort BEFORE enrolling if any bait path is occupied, so a refused install
    # never registers an endpoint (no ghost in the dashboard, issue #29).
    [ "$FORCE" = 1 ] || preflight_paths || exit 1

    do_enroll || { err "enroll failed"; exit 1; }
    pull_deployments || { err "no deployments pulled"; exit 1; }

    [ -n "$TARGET_USER" ] && log "running as root; bait will be owned by $TARGET_USER ($TARGET_HOME)"

    plant_all
    [ "$planted" -gt 0 ] || { log "no bait planted; nothing to watch"; return 0; }

    if [ "$SIMULATE" = "1" ]; then
        i=1
        while [ "$i" -le "$DEP_COUNT" ]; do
            fire "$i" open simulated "$$" "${USER:-$(id -un)}" ""
            i=$((i + 1))
        done
        # --simulate exits before the cleanup traps are armed, so clean up now:
        # sweep any FIFO bait (a leftover no-reader pipe blocks every real open()
        # forever) AND remove the cached fake-credential content it planted -
        # test-only mode shouldn't leave either behind (Roee #123 F2). Sweep
        # unconditionally: a per-deployment sensor can plant FIFOs even when the
        # global FIFO_MODE is 0 (Linux with dep_sensor=fifo) (Roee #160 N3).
        remove_fifos
        [ -n "${BAITCACHE:-}" ] && [ -d "$BAITCACHE" ] && rm -rf "$BAITCACHE"
        return 0
    fi
    [ "$ONCE" = "1" ] && return 0

    HEARTBEAT_PID=""
    if [ "$HEARTBEAT" -gt 0 ] 2>/dev/null; then
        heartbeat_loop &
        HEARTBEAT_PID=$!
        log "heartbeat every ${HEARTBEAT}s (pid $HEARTBEAT_PID)"
    fi

    # On any exit: stop the background watcher, kill the heartbeat loop, AND
    # release the singleton lock. Combined into one trap (replacing the release-
    # only trap set after acquire_singleton) so none clobbers the others.
    cleanup_heartbeat() { [ -n "$HEARTBEAT_PID" ] && kill "$HEARTBEAT_PID" 2>/dev/null; }
    trap 'stop_watcher; remove_fifos; cleanup_heartbeat; release_singleton; exit 0' INT TERM
    trap 'stop_watcher; remove_fifos; cleanup_heartbeat; release_singleton' EXIT
    # Remote kill: the heartbeat loop raises USR1 when the server flags us.
    trap 'self_destruct' USR1

    if [ "$EPHEMERAL" = 1 ]; then
        # CI per-job endpoint: on job end / SIGTERM, fully decommission (unplant +
        # tell the server to drop the row) instead of just releasing the lock.
        trap 'self_destruct' INT TERM EXIT
    fi

    start_watcher
    # The steady-state `ready` marker is now written by the watcher itself, once
    # workers are up and (for atime) baselines are captured - accurate in every
    # mode, not just ephemeral, and no longer racing the sub-second startup (#237).

    # No live sync: behave as before - block on the watcher.
    if ! [ "$SYNC_INTERVAL" -gt 0 ] 2>/dev/null; then
        wait "$WATCH_PID" || true
        return 0
    fi

    # Live sync: re-pull on an interval; restart the watcher on a real change or crash.
    while true; do
        sleep "$SYNC_INTERVAL"
        # The watcher is a separate background process. A transient sensor crash
        # must not leave the still-running sync loop permanently blind. This check
        # runs at most once per sync interval, which is also a natural backoff
        # when the underlying failure persists (#99).
        if ! watcher_identity_matches; then
            log "watcher exited unexpectedly - restarting"
            # Reap the original child job before cleaning its orphan registry.
            # If its PID was reused, wait still cannot target the unrelated process.
            [ -n "${WATCH_PID:-}" ] && wait "$WATCH_PID" 2>/dev/null || true
            WATCH_PID=""
            WATCH_STARTED=""
            cleanup_watcher_workers
            start_watcher
        fi
        _old=$(snapshot | sort)
        # A failed pull is often a dead token (DB reset / re-enroll needed), which
        # would otherwise retry forever - recover via resync (re-enroll, rate-
        # limited). On success FALL THROUGH so the refreshed set is reconciled;
        # only skip the cycle if recovery itself fails.
        if ! pull_deployments && ! resync; then
            continue
        fi
        # Sort both sides: snapshot emits in server order, so a pure reorder is NOT
        # a real change and must not trigger a needless watcher restart.
        _new=$(snapshot | sort)
        if [ "$_old" != "$_new" ]; then
            log "deployment set changed - reconciling"
            stop_watcher
            reconcile "$_old"
            start_watcher
        fi
        REPLANTED=0
        verify_planted   # every cycle, even when the set did not change
        if [ "$REPLANTED" = 1 ]; then
            # A re-plant gives the bait a new inode/timestamp, which every sensor's
            # per-bait state depends on: a FIFO needs re-serving, an atime bait
            # needs re-arming (else its stale year-2000 baseline fires a ghost
            # alert), an inotify watch needs re-pointing at the new inode. Restart
            # regardless of platform/mode (FIFO_MODE is 0 on Linux even for FIFOs).
            log "re-planted bait - restarting watcher to re-arm/re-serve it"
            stop_watcher
            start_watcher
        fi
    done
}

# ── arg parsing (POSIX) ───────────────────────────────────────────────────────
usage_text() {
    cat <<EOF
usage: thumper_agent.sh run --server URL --enroll-token TOKEN [options]
  --help, -h           print this help and exit
  --version            print the agent version and exit
  --tripwire ID        tripwire to apply (repeatable)
  --state-file PATH    state file (default: $DEFAULT_STATE)
  --poll SECONDS       atime poll interval (default: 5)
  --sensor MODE        read sensor: auto|fifo|atime (default: auto). atime plants a
                       regular-file bait + re-armable atime tripwire (no pid)
  --heartbeat SECONDS  heartbeat interval; 0 to disable (default: 60)
  --sync-interval SECS re-pull deployments + reconcile every SECS (default: 300, 0 disables)
  --once               enroll + plant, then exit
  --simulate           fire a signed callback for each deployment, then exit
  --force              overwrite a path even if a file we didn't plant is there
  --ephemeral          per-job CI endpoint; auto-decommissions on exit
EOF
}

usage() {
    code=${1:-2}
    if [ "$code" = 0 ]; then
        usage_text
    else
        usage_text >&2
    fi
    exit "$code"
}

SERVER=""; ENROLL_TOKEN=""; TRIPWIRES=""; STATE_FILE=""; POLL=5; HEARTBEAT=60; SYNC_INTERVAL=300; ONCE=0; SIMULATE=0; FORCE=0; EPHEMERAL=0; SENSOR=auto

case "${1:-}" in
    --help|-h) usage 0 ;;
    --version) printf '%s\n' "$AGENT_VERSION"; exit 0 ;;
esac

[ "${1:-}" = "run" ] || usage
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)      usage 0 ;;
        --version)      printf '%s\n' "$AGENT_VERSION"; exit 0 ;;
        --server)       SERVER=$2; shift 2 ;;
        --enroll-token) ENROLL_TOKEN=$2; shift 2 ;;
        --tripwire)     TRIPWIRES="${TRIPWIRES:+$TRIPWIRES,}$2"; shift 2 ;;
        --state-file)   STATE_FILE=$2; shift 2 ;;
        --poll)         is_uint "${2:-}" || { err "--poll must be a non-negative integer"; exit 2; }; POLL=$2; shift 2 ;;
        --heartbeat)    is_uint "${2:-}" || { err "--heartbeat must be a non-negative integer"; exit 2; }; HEARTBEAT=$2; shift 2 ;;
        --sync-interval) is_uint "${2:-}" || { err "--sync-interval must be a non-negative integer"; exit 2; }; SYNC_INTERVAL=$2; shift 2 ;;
        --sensor)       SENSOR=$2; shift 2 ;;
        --once)         ONCE=1; shift ;;
        --simulate)     SIMULATE=1; shift ;;
        --force)        FORCE=1; shift ;;
        --ephemeral)    EPHEMERAL=1; shift ;;
        *) err "unknown argument: $1"; usage ;;
    esac
done
[ -n "$SERVER" ] && [ -n "$ENROLL_TOKEN" ] || usage
case "$SENSOR" in auto|fifo|atime) ;; *) err "invalid --sensor: $SENSOR (want auto|fifo|atime)"; usage ;; esac

for tool in curl openssl; do
    command -v "$tool" >/dev/null 2>&1 || { err "$tool is required"; exit 1; }
done

run
