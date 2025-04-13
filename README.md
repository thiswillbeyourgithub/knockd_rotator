# Knock Rotator

A security-enhanced port knocking system with rotating knock sequences.

## Overview

This project provides tools to enhance the security of [knockd](https://github.com/jvinet/knock) port knocking by automatically rotating knock sequences based on time periods. This prevents replay attacks and significantly improves the security of your port knocking setup.

The rotating sequence is deterministically generated based on:
- The timestamp at the beginning of the current time period (UNIX seconds floored to a multiple of the period length)
- A unique service name
- A pre-shared secret

This means that legitimate clients and servers will independently generate the same sequence for each time period, while attackers cannot predict future sequences without knowing the secret.

## How It Works

Both the server and client independently generate the same knock sequence for a given time period:

1. The client uses `knockd_rotator_client.py` to generate the current sequence and performs the knocks
2. The server runs `knockd_rotator_server.py` periodically (via systemd timer) to:
   - Update `/etc/knockd.conf` with the current sequences
   - Restart the knockd service to apply changes
   - Sometimes schedule an anticipated run to ensure timely updates at period boundaries

The shared sequence generation algorithm ensures both sides produce identical sequences without any communication between them.

## Components

### knockd_rotator_client.py (v1.0.1)

A lightweight client-side tool that both generates and executes knock sequences:

- Runs on minimal environments like [Termux](https://termux.dev/) on Android
- Requires only Python 3 standard library
- Supports abbreviated commands (e.g. "gene" for "generate", "knock" for "knock")
- Supports two modes:
  - **Generate mode**: Creates the sequence string for a service
    - Usage: `./knockd_rotator_client.py generate <service_name> [--offset <n>]`
  - **Knock mode**: Performs the actual port knocking against a target host
    - Usage: `./knockd_rotator_client.py knock <host> <service_name> [--offset <n>]`
- Automatically appends "_ROTATOR" to service names if not already present
- Supports time period offsets to generate past or future sequences

### knockd_rotator_server.py (v1.0.1)

A server-side tool that:

- Scans `/etc/knockd.conf` for sections ending with `_ROTATOR`
- Updates those sections with freshly generated sequences
- Restarts the knockd service after updating
- Verifies that the service is running correctly after restart
- Intelligently schedules an additional run to handle period transitions
- Supports dry-run mode for testing
- Usage: `./knockd_rotator_server.py [--dry-run] [--config /path/to/knockd.conf]`

## Configuration

The system is configured through environment variables:

- `KNOCKD_ROTATOR_LENGTH`: Number of ports in the knock sequence (default: 10)
- `KNOCKD_ROTATOR_SECRET`: The shared secret used to generate sequences (required, minimum 10 characters)
- `KNOCKD_ROTATOR_PORT_MODULO`: Controls TCP/UDP protocol selection:
  - When `KNOCKD_ROTATOR_PORT_MODULO = 0` (default): All knocks use TCP protocol
  - When `KNOCKD_ROTATOR_PORT_MODULO > 0`: Port modulo MODULO determines protocol (even = TCP, odd = UDP)
- `KNOCKD_ROTATOR_PERIOD_MODULO`: Controls how frequently the sequence changes, in seconds (default: 21600, which is 6 hours)
- `KNOCKD_ROTATOR_SERVER_INTERVAL`: How often the server script is expected to run, in seconds (default: 3600, which is 1 hour). This is used to know if we should fork the process to anticipate the next period.

Port numbers are generated in the range 2000-65535 to avoid requiring elevated privileges.

## Example knockd.conf Section

```
[ssh_ROTATOR]
sequence    = 12345:tcp,23456:tcp,34567:tcp,45678:tcp,56789:tcp,65432:tcp
seq_timeout = 15
tcpflags    = syn
start_command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
cmd_timeout   = 30
stop_command  = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

## Setup

1. Install knockd on your server
2. Configure your knockd.conf with sections ending in `_ROTATOR`
3. Set up the systemd service and timer:
   - Copy `knockd_rotator.service` and `knockd_rotator.timer` to `/etc/systemd/system/`
   - Enable and start the timer: `systemctl enable --now knockd_rotator.timer`
4. Distribute the client script to your devices:
   - Copy `knockd_rotator_client.py` to your client devices
   - Set the same environment variables on clients as on the server

## Advanced Features

- **Period Boundary Handling**: The server automatically schedules an additional run at period transitions to ensure timely sequence updates
- **Service Verification**: Confirms knockd is running properly after configuration changes
- **Multiple Services**: Support for multiple different rotator services in one config file
- **Time Period Offsets**: Generate past or future sequences with the `--offset` parameter. This is useful to generate sequences that were valid at passed times if you know that the server side script failed to run for some reason.

## Notes

- I am *obviously* not a security expert.
- This works fine using `ufw` in my tests.
- I don't advise using a very frequent rotation unless you don't use knockd's `start_command` and `stop_command` because if it happens between the two you might end up in a compromised state.
- The code is minimal on purpose so that you just have to copy the `knockd_rotator_client.py` file around and the env variables.
- User @rdmitry0911 made [a pull request](https://github.com/jvinet/knock/pull/76) to include a somewhat similar feature directly in knockd. Their implementation is based on OTP whereas this project uses pure Python for the sequence generation.
- Knockd already includes a feature to have knock sequences taken from a text file and used only once at a time. However, I wanted to be able to perform knocks from multiple clients without issues, so I created this solution which deterministically generates the same sequence across all clients for a given time period.

This project was developed with the assistance of [aider.chat](https://github.com/Aider-AI/aider/issues).
