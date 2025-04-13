#!/usr/bin/env python3

import sys
import re
import argparse
import subprocess
import time
import os
import datetime
from typing import List, Tuple

# Import necessary functions and constants from knockd_rotator_client.py
from knockd_rotator_client import (
    generate_knock_sequence,
    __SHARED_SEED__,
    calculate_shared_seed,
    PERIOD_MODULO,
)

# Verify the imported shared_seed is current
current_seed = calculate_shared_seed()
if __SHARED_SEED__ != current_seed:
    print(
        f"Error: Imported shared_seed ({__SHARED_SEED__}) is out of sync with current time period ({current_seed})"
    )
    print("This could happen if the module was imported across a time period boundary.")
    sys.exit(1)

__VERSION__: str = "1.0.1"

# How frequently this server is expected to run (in seconds)
SERVER_RUN_INTERVAL = int(
    os.environ.get("KNOCKD_ROTATOR_SERVER_INTERVAL", 3600)
)  # Default: 1 hour

DEFAULT_CONFIG_FILE = "/etc/knockd.conf"


def parse_sequence(sequence_str: str) -> List[Tuple[int, str]]:
    """
    Parse a knockd sequence string into port and protocol tuples.

    Args:
        sequence_str: The sequence string from knockd.conf (space or comma separated)

    Returns:
        List of (port, protocol) tuples
    """
    # Support both comma and space separated formats
    if "," in sequence_str:
        parts = sequence_str.split(",")
    else:
        parts = sequence_str.split()

    result = []

    for part in parts:
        part = part.strip()
        if ":" in part:
            port_str, protocol = part.split(":")
            port = int(port_str.strip())
        else:
            # If no protocol specified, default to tcp
            port = int(part)
            protocol = "tcp"

        result.append((port, protocol))

    return result


def process_knockd_conf(config_file: str, dry_run: bool = False) -> bool:
    """
    Process the knockd.conf file and update time based sequences.

    Args:
        config_file: Path to the knockd.conf file
        dry_run: If True, don't write changes back to the file
    """
    try:
        with open(config_file, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {config_file}: {e}")
        sys.exit(1)

    print(f"Using shared seed: {current_seed} (Based on current time period)")

    # Track state
    current_section = None
    modified_lines = []
    old_sequences = {}
    new_sequences = {}
    changes_needed = False

    # Regular expressions for matching sections and sequences
    section_pattern = re.compile(r"^\s*\[(.*_ROTATOR)\]\s*$")
    sequence_pattern = re.compile(r"^\s*sequence\s*=\s*(.+)\s*$")

    # Process each line
    for i, line in enumerate(lines):
        # Skip comment lines
        if line.lstrip().startswith("#"):
            modified_lines.append(line)
            continue

        # Check if line is a section header
        section_match = section_pattern.match(line)
        if section_match:
            if current_section and current_section not in old_sequences:
                print(f"Warning: No sequence found for section {current_section}")

            current_section = section_match.group(1)
            print(f"Found rotator sequence section: {current_section}")
            modified_lines.append(line)
            continue

        # Check if line is a sequence and we're in a rotator sequence section
        if current_section and sequence_pattern.match(line):
            seq_match = sequence_pattern.match(line)
            old_sequence = seq_match.group(1)
            old_sequences[current_section] = old_sequence

            # Generate new sequence for this section
            new_sequence = generate_knock_sequence(current_section)
            # Convert space-separated to comma-separated format
            new_sequence = new_sequence.replace(" ", ",")
            new_sequences[current_section] = new_sequence

            # Print debug info
            print(f"  Old sequence for {current_section}: {old_sequence}")
            print(f"  New sequence for {current_section}: {new_sequence}")

            # Check if sequence needs to be updated
            if old_sequence != new_sequence:
                changes_needed = True
                # Replace the sequence
                indent = re.match(r"(\s*)", line).group(1)
                modified_lines.append(f"{indent}sequence    = {new_sequence}\n")
            else:
                print(f"  Sequence unchanged for {current_section}")
                modified_lines.append(line)

            # If we find another section, stop being in the current section
            if i + 1 < len(lines) and "[" in lines[i + 1] and "]" in lines[i + 1]:
                current_section = None
        else:
            modified_lines.append(line)

    # Verify all sections have sequences
    if current_section and current_section not in old_sequences:
        print(f"Warning: No sequence found for section {current_section}")
        sys.exit(1)

    # Verify sequences are unique
    if not new_sequences:
        print("Warning: No rotator sequence sections found in the config file")
        sys.exit(1)

    unique_sequences = set(new_sequences.values())
    if len(unique_sequences) < len(new_sequences):
        print("Warning: Not all generated sequences are unique")
        # Print which sequences are duplicated
        sequence_counts = {}
        for section, sequence in new_sequences.items():
            if sequence not in sequence_counts:
                sequence_counts[sequence] = []
            sequence_counts[sequence].append(section)

        for sequence, sections in sequence_counts.items():
            if len(sections) > 1:
                print(
                    f"  Sequence {sequence} is used by sections: {', '.join(sections)}"
                )
        sys.exit(1)

    # Write back the modified file if not in dry-run mode and changes are needed
    if not changes_needed:
        print("No changes needed - all sequences are already up to date")
    elif not dry_run:
        try:
            with open(config_file, "w") as f:
                f.writelines(modified_lines)
            print(f"Updated {config_file} with new sequences")
        except Exception as e:
            print(f"Error writing to {config_file}: {e}")
            sys.exit(1)
    else:
        print("Dry run - no changes were written to the file")

    return changes_needed


def schedule_next_run_if_needed():
    """
    Check if we need to schedule an additional run before the next expected run.
    This ensures we update the sequence within 5 minutes of a new period starting.
    """
    # Get current time and when we expect to run next
    current_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
    next_expected_run = current_time + SERVER_RUN_INTERVAL

    # Calculate when the next period starts
    current_period_start = (current_time // PERIOD_MODULO) * PERIOD_MODULO
    next_period_start = current_period_start + PERIOD_MODULO

    # 5 minutes buffer (300 seconds)
    buffer_time = 300

    # If our next expected run would be more than 5 minutes after the start of a new period
    scheduled_run_time = next_period_start + 60
    sleep_duration = scheduled_run_time - current_time
    print(
        f"Next period starts at {datetime.datetime.fromtimestamp(next_period_start, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    time_until_next_period = next_period_start - current_time
    print(f"Time until next period: {int(time_until_next_period)} seconds ({time_until_next_period/3600:.2f} hours)")
    if next_expected_run > next_period_start + buffer_time:
        # Schedule a run for 1 minute after the next period starts
        print(
            f"Scheduling additional run at {datetime.datetime.fromtimestamp(scheduled_run_time, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        print(f"(in {sleep_duration:.1f} seconds)")

        # Use systemd-run to schedule the next run with proper logging
        try:
            cmd = sys.argv.copy()
            systemd_cmd = [
                "systemd-run", 
                "--on-active", f"{int(sleep_duration)}s",
                "--unit", f"knockd-rotator-period-change-{int(next_period_start)}",
                "--description", f"Scheduled knockd-rotator run for period change at {int(next_period_start)}"
            ]
            systemd_cmd.extend(cmd)
            
            result = subprocess.run(
                systemd_cmd,
                capture_output=True, 
                text=True, 
                check=True
            )
            print(f"Scheduled via systemd: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to schedule via systemd: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            
            # Fall back to a background process but redirect to a log file
            print("Falling back to manual scheduling...")
            log_file = f"/var/log/knockd_rotator_scheduled_{int(next_period_start)}.log"
            cmd_str = f"sleep {sleep_duration} && {' '.join(cmd)} > {log_file} 2>&1"
            daemon_process = subprocess.Popen(
                ["sh", "-c", cmd_str],
                start_new_session=True,
            )
            print(f"Daemon process started with PID {daemon_process.pid}, logging to {log_file}")


def check_knockd_service() -> bool:
    """
    Check if knockd service is running.

    Returns:
        True if running, False otherwise
    """
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "status", "knockd.service"],
            capture_output=True,
            text=True,
            check=False,
        )
        # If the command returns 0, the service is running
        return result.returncode == 0 and "active (running)" in result.stdout
    except Exception as e:
        print(f"Error checking knockd service status: {e}")
        return False


def main():
    """Main function to parse arguments and run the program."""
    parser = argparse.ArgumentParser(description="Update knockd rotator sequences")
    parser.add_argument(
        "--dry-run", action="store_true", help="Do not write changes back to the file"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to knockd.conf (default: {DEFAULT_CONFIG_FILE})",
    )
    args = parser.parse_args()

    # Process the config file and get whether changes were made
    changes_made = process_knockd_conf(args.config, args.dry_run)

    # If we're not in dry-run mode and changes were made, restart the service
    if not args.dry_run and changes_made:
        # Check if service is running
        if not check_knockd_service():
            print("Error: knockd service is not running!")
            sys.exit(1)

        # Restart the service
        print("Restarting knockd service...")
        try:
            subprocess.run(
                ["sudo", "systemctl", "restart", "knockd.service"], check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Error restarting knockd service: {e}")
            sys.exit(1)

        # Wait 5 seconds
        print("Waiting 5 seconds for service to stabilize...")
        time.sleep(5)

        # Check again that service is running
        if not check_knockd_service():
            print("Error: knockd service failed to restart!")
            sys.exit(1)

        print("knockd service successfully restarted.")

    # Check if we need to schedule another run before the next expected run
    schedule_next_run_if_needed()


if __name__ == "__main__":
    main()
