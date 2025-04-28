#!/usr/bin/env zsh

# Pure Zsh implementation of knockd_rotator_client.py
# Version: 3.0.0 (matches Python client version)

# Load Zsh TCP module (required)
zmodload zsh/net/tcp 2>/dev/null || { echo "Error: zsh/net/tcp module not found. Cannot perform TCP knocks." >&2; exit 1; }

# Try loading UDP module (optional, fallback exists)
integer udp_module_loaded=0
if zmodload zsh/net/udp 2>/dev/null; then
    udp_module_loaded=1
else
    # Warn only if UDP might actually be used
    if (( ${KNOCKD_ROTATOR_PROTO_MODULO:-0} > 0 )); then
        echo "Warning: zsh/net/udp module not found. UDP knocks will use fallback (/dev/udp)." >&2
    fi
fi

# Check for required external commands
_check_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Error: Required command '$1' not found in PATH." >&2
        exit 1
    }
}
_check_cmd bc # Required for floating point math

# --- Configuration from Environment Variables ---

# Sequence Length
# Default: 10
integer KNOCKD_ROTATOR_LENGTH=${KNOCKD_ROTATOR_LENGTH:-10}
if (( KNOCKD_ROTATOR_LENGTH < 5 )); then
  echo "Error: KNOCKD_ROTATOR_LENGTH must be at least 5" >&2
  exit 1
fi
readonly SEQUENCE_LENGTH=$KNOCKD_ROTATOR_LENGTH

# Secret (Required)
if [[ -z "$KNOCKD_ROTATOR_SECRET" ]]; then
  echo "Error: KNOCKD_ROTATOR_SECRET environment variable must be set" >&2
  exit 1
elif (( ${#KNOCKD_ROTATOR_SECRET} < 10 )); then
  echo "Error: KNOCKD_ROTATOR_SECRET must be at least 10 characters long" >&2
  exit 1
fi
readonly SECRET="$KNOCKD_ROTATOR_SECRET"

# Protocol Modulo
# Default: 0 (always TCP)
integer KNOCKD_ROTATOR_PROTO_MODULO=${KNOCKD_ROTATOR_PROTO_MODULO:-0}
readonly PROTO_MODULO=$KNOCKD_ROTATOR_PROTO_MODULO

# Period Modulo
# Default: 21600 (6 hours)
integer KNOCKD_ROTATOR_PERIOD_MODULO=${KNOCKD_ROTATOR_PERIOD_MODULO:-21600}
if [[ -z "$KNOCKD_ROTATOR_PERIOD_MODULO_SET" && "$KNOCKD_ROTATOR_PERIOD_MODULO" -eq 21600 ]]; then
    # Check if the variable was explicitly set to the default value
    # This requires running the script with KNOCKD_ROTATOR_PERIOD_MODULO_SET=1 if the default is intended
    # A simpler check is just to see if the env var exists at all
    if ! printenv KNOCKD_ROTATOR_PERIOD_MODULO >/dev/null; then
        echo "Warning: KNOCKD_ROTATOR_PERIOD_MODULO not set, using default of 21600 (6 hours)" >&2
    fi
fi
readonly PERIOD_MODULO=$KNOCKD_ROTATOR_PERIOD_MODULO

# Ports
# Default: 2000-65536
local port_str=${KNOCKD_ROTATOR_PORTS:-"2000-65536"}
typeset -a PORTS_RAW
typeset -a PORTS
typeset -A port_seen # Associative array to check for duplicates

# Parse port string (comma-separated, ranges allowed)
IFS=',' read -rA PORTS_RAW <<< "$port_str"
for part in "${PORTS_RAW[@]}"; do
  part=$(echo "$part" | tr -d '[:space:]') # Trim whitespace
  if [[ "$part" == *-* ]]; then
    local start end
    start=$(echo "$part" | cut -d'-' -f1)
    end=$(echo "$part" | cut -d'-' -f2)
    if ! [[ "$start" =~ ^[0-9]+$ ]] || ! [[ "$end" =~ ^[0-9]+$ ]] || (( start > end )); then
        echo "Error: Invalid port range format in KNOCKD_ROTATOR_PORTS: '$part'" >&2
        exit 1
    fi
    # Generate sequence including both ends
    for (( i=start; i<=end; i++ )); do
      if [[ -n ${port_seen[$i]} ]]; then
        echo "Error: Duplicate port $i found in KNOCKD_ROTATOR_PORTS" >&2
        exit 1
      fi
      port_seen[$i]=1
      PORTS+=("$i")
    done
  elif [[ "$part" =~ ^[0-9]+$ ]]; then
    if [[ -n ${port_seen[$part]} ]]; then
        echo "Error: Duplicate port $part found in KNOCKD_ROTATOR_PORTS" >&2
        exit 1
    fi
    port_seen[$part]=1
    PORTS+=("$part")
  elif [[ -n "$part" ]]; then # Ignore empty parts resulting from trailing commas etc.
    echo "Error: Invalid port format in KNOCKD_ROTATOR_PORTS: '$part'" >&2
    exit 1
  fi
done

# Ensure at least 2 ports
if (( ${#PORTS[@]} < 2 )); then
  echo "Error: KNOCKD_ROTATOR_PORTS must contain at least 2 ports (found ${#PORTS[@]})" >&2
  exit 1
fi

# Warn if 3 or fewer ports
if (( ${#PORTS[@]} <= 3 )); then
  echo "Warning: Only ${#PORTS[@]} ports available. This significantly reduces security." >&2
fi

# Sort ports numerically for consistency
PORTS=(${(n)PORTS})
readonly PORTS # Make the final array readonly

# Minimum entropy required (in bits)
readonly MIN_ENTROPY_BITS=40

# --- Helper Functions ---

# Calculate log base 2 using bc
# Usage: _log2 number
_log2() {
    local num=$1
    # bc requires integer check first
    # Redirect bc stderr in the condition to suppress syntax errors on invalid input
    if ! [[ "$num" =~ ^[0-9]+(\.[0-9]+)?$ ]] || (( $(echo "$num <= 1" | bc -l 2>/dev/null) )); then
        echo 0 # Return 0 for numbers <= 1
        return
    fi
    # Use bc for log calculation: l(x) is natural log
    echo "l($num)/l(2)" | bc -l
}

# Calculate knock entropy
# Usage: calculate_knock_entropy sequence_length port_count
calculate_knock_entropy() {
    local seq_len=$1
    local port_count=$2
    if (( port_count <= 1 )); then
        echo "0.00" # Return "0.00" for count <= 1
        return
    fi
    local log2_ports=$(_log2 $port_count)
    # Use bc for multiplication and printf for formatting
    local result=$(echo "$seq_len * $log2_ports" | bc -l)
    printf "%.2f\n" "$result"
}

# Calculate shared seed based on time period
# Usage: calculate_shared_seed [offset]
calculate_shared_seed() {
    local offset=${1:-0}
    integer current_timestamp
    # Get UTC timestamp
    current_timestamp=$(date -u +%s)
    if [[ $? -ne 0 || -z "$current_timestamp" ]]; then
        echo "Error: Failed to get current UTC timestamp using 'date -u +%s'" >&2
        exit 1
    fi

    integer period_start
    period_start=$(( ( (current_timestamp / PERIOD_MODULO) + offset ) * PERIOD_MODULO ))

    if (( period_start == 0 )); then
        echo "Error: Calculated period start is zero, check PERIOD_MODULO and system time." >&2
        exit 1
    fi
    # Basic sanity check on length
    if (( ${#period_start} <= 5 )); then
        echo "Warning: Suspiciously short period start value: $period_start" >&2
    fi
    echo $period_start
}

# Generate knock sequence for a service
# Usage: generate_knock_sequence service_name [offset]
generate_knock_sequence() {
    local service_name=$1
    local offset=${2:-0}
    local -a sequence_parts

    # Calculate and check entropy
    local entropy_bits=$(calculate_knock_entropy $SEQUENCE_LENGTH ${#PORTS[@]})
    # Use bc for float comparison
    local comparison=$(echo "$entropy_bits < $MIN_ENTROPY_BITS" | bc -l)
    if (( comparison == 1 )); then
        local error_msg="Insufficient entropy: ${entropy_bits} bits. Required minimum: ${MIN_ENTROPY_BITS} bits. Increase SEQUENCE_LENGTH or add more ports."
        echo "Error: $error_msg" >&2
        # Mimic Python's ValueError by exiting
        exit 1 # Or return an error status? Exiting matches Python better.
    fi

    # Ensure service_name ends with _ROTATOR
    if [[ "$service_name" != *_ROTATOR ]]; then
        service_name="${service_name}_ROTATOR"
    fi

    # Calculate seed for this period and service
    local current_seed=$(calculate_shared_seed $offset)
    if [[ $? -ne 0 ]]; then exit 1; fi # Exit if seed calculation failed

    local section_seed="${current_seed}${service_name}${SECRET}"

    # Check for sha256sum or openssl
    local sha_cmd
    if command -v sha256sum >/dev/null 2>&1; then
        sha_cmd="sha256sum"
    elif command -v openssl >/dev/null 2>&1; then
        sha_cmd="openssl"
    else
        echo "Error: Neither 'sha256sum' nor 'openssl' found. Cannot generate hash." >&2
        exit 1
    fi

    # Generate the ports
    integer i=1
    while (( i <= SEQUENCE_LENGTH )); do
        local hash_input="${section_seed}${i}"
        local hash_value
        # Generate SHA256 hash and extract hex digest
        if [[ "$sha_cmd" == "sha256sum" ]]; then
            hash_value=$(print -n "$hash_input" | sha256sum | cut -d ' ' -f 1)
        else # openssl
            # openssl dgst output format is "SHA256(stdin)= hexhash" or "(stdin)= hexhash"
            hash_value=$(print -n "$hash_input" | openssl dgst -sha256 | sed 's/^.* //')
        fi

        if [[ -z "$hash_value" ]]; then
            echo "Error: Failed to generate hash for iteration $i" >&2
            exit 1
        fi

        # Take first 8 hex chars and convert to decimal
        local hex_part=${hash_value:0:8}
        integer decimal=$(( 16#$hex_part ))

        # Select a port from our port list (Zsh arrays are 1-based)
        integer port_index=$(( (decimal % ${#PORTS[@]}) + 1 ))
        local port=${PORTS[$port_index]}

        # Basic validation (should always be in list due to modulo)
        if [[ -z "$port" ]]; then
            echo "Error: Calculated invalid port index $port_index for decimal $decimal" >&2
            exit 1
        fi

        # Determine protocol
        local proto="tcp" # Default
        if (( PROTO_MODULO > 0 )); then
            if (( port % PROTO_MODULO != 0 )); then
                proto="udp"
            fi
        fi

        # Add to sequence parts
        sequence_parts+=("${port}:${proto}")

        (( i++ ))
    done

    # Join parts with space
    echo "${sequence_parts[@]}"
}

# Perform port knocking
# Usage: knock_ports host sequence_string
knock_ports() {
    local host=$1
    local sequence_str=$2
    local -a sequence_parts
    sequence_parts=(${(s: :)sequence_str}) # Split sequence string by space

    # Check for timeout command
    _check_cmd timeout

    for port_proto in "${sequence_parts[@]}"; do
        local port proto
        port=$(echo "$port_proto" | cut -d':' -f1)
        proto=$(echo "$port_proto" | cut -d':' -f2)

        if [[ "$proto" == "udp" ]]; then
            echo "Knocking UDP port $port..."
            local udp_knock_success=0
            # Try ztcp if module loaded and command exists
            if (( udp_module_loaded == 1 )) && command -v ztcp >/dev/null 2>&1; then
                 timeout 0.5s ztcp -u $host $port < /dev/null 2>/dev/null
                 # We assume success if timeout doesn't return error other than 124 (timeout)
                 local exit_status=$?
                 if (( exit_status == 0 || exit_status == 124 )); then
                    udp_knock_success=1
                 fi
            fi

            # Fallback to /dev/udp if ztcp wasn't successful or wasn't attempted
            if (( udp_knock_success == 0 )); then
                 # Use timeout to prevent hangs if /dev/udp behaves unexpectedly.
                 timeout 0.5s zsh -c "print -n '' > /dev/udp/$host/$port" 2>/dev/null
                 local exit_status=$?
                 # Check if timeout itself failed (non-zero, non-124) or if zsh command failed
                 if ! (( exit_status == 0 || exit_status == 124 )); then
                    echo "Warning: UDP knock to $host:$port using /dev/udp may have failed (status $exit_status)." >&2
                 fi
                 # We consider the attempt made, even if it might have failed silently.
            fi

        elif [[ "$proto" == "tcp" ]]; then
            echo "Knocking TCP port $port..."
            # Try to connect using /dev/tcp with a timeout
            # The 'exec {fd}<>/dev/tcp/...' approach is cleaner but harder to timeout reliably
            # Using 'timeout' with a subshell is more robust for this purpose.
            timeout 1s zsh -c "exec 3<>/dev/tcp/$host/$port && exec 3>&-" >/dev/null 2>&1
            # We ignore the exit status of timeout/zsh here, as connection refused is expected.
        else
            echo "Error: Unknown protocol '$proto' in sequence" >&2
            # Decide whether to continue or exit? Python client continues.
        fi

        # Small delay between knocks
        sleep 0.1
    done
    echo "Knocking sequence complete."
}

# --- Main Execution ---

# Calculate and display entropy information
entropy_bits=$(calculate_knock_entropy $SEQUENCE_LENGTH ${#PORTS[@]})
echo "Knock sequence entropy: ${entropy_bits} bits"
comparison=$(echo "$entropy_bits < $MIN_ENTROPY_BITS" | bc -l)
if (( comparison == 1 )); then
    echo "WARNING: Current configuration has low entropy (${entropy_bits} bits)" >&2
    echo "Minimum recommended entropy: ${MIN_ENTROPY_BITS} bits" >&2
fi

# Argument Parsing
zparseopts -D -E -A args -- \
    o:=offset_opt -offset:=offset_opt

local mode=""
local service_name=""
local host=""
local offset=0

# Check for offset argument
if [[ -n "${offset_opt[2]}" ]]; then
    if [[ "${offset_opt[2]}" =~ ^[-+]?[0-9]+$ ]]; then
        offset=${offset_opt[2]}
    else
        echo "Error: --offset value must be an integer." >&2
        exit 1
    fi
fi

# Determine mode and remaining arguments
if [[ "$1" == "generate" || "$1" == "gen" ]]; then
    mode="generate"
    shift
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 generate [--offset N] <service_name>" >&2
        exit 1
    fi
    service_name=$1
elif [[ "$1" == "knock" || "$1" == "kno" ]]; then
    mode="knock"
    shift
    if [[ $# -ne 2 ]]; then
        echo "Usage: $0 knock [--offset N] <host> <service_name>" >&2
        exit 1
    fi
    host=$1
    service_name=$2
else
    # Allow abbreviated commands if not using zparseopts for positional args
    # This part handles the abbreviation logic similar to the Python script's simple check
    if [[ $# -gt 0 ]]; then
        if [[ "generate" == $1* ]]; then
             mode="generate"
             shift
             if [[ $# -ne 1 ]]; then
                 echo "Usage: $0 generate [--offset N] <service_name>" >&2
                 exit 1
             fi
             service_name=$1
        elif [[ "knock" == $1* ]]; then
             mode="knock"
             shift
             if [[ $# -ne 2 ]]; then
                 echo "Usage: $0 knock [--offset N] <host> <service_name>" >&2
                 exit 1
             fi
             host=$1
             service_name=$2
        fi
    fi

    if [[ -z "$mode" ]]; then
        echo "Usage: $0 {generate|knock} [options] ..." >&2
        echo "  $0 generate [--offset N] <service_name>" >&2
        echo "  $0 knock [--offset N] <host> <service_name>" >&2
        exit 1
    fi
fi


# Execute selected mode
if [[ "$mode" == "generate" ]]; then
    sequence=$(generate_knock_sequence "$service_name" "$offset")
    if [[ $? -eq 0 ]]; then
        echo "$sequence"
    else
        exit 1 # Error occurred during generation
    fi
elif [[ "$mode" == "knock" ]]; then
    sequence=$(generate_knock_sequence "$service_name" "$offset")
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to generate sequence for knocking." >&2
        exit 1
    fi
    echo "Generated sequence: $sequence" # Optional: show sequence before knocking
    knock_ports "$host" "$sequence"
else
    # This case should not be reachable due to earlier checks
    echo "Error: Unknown mode '$mode'" >&2
    exit 1
fi

exit 0
