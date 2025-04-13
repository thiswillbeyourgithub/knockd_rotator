# Knock Rotator

A security-enhanced port knocking system with rotating knock sequences.

## Overview

This project provides tools to enhance the security of [knockd](https://github.com/jvinet/knock) port knocking by automatically rotating knock sequences as often as you want. This prevents replay attacks and significantly improves the security of your port knocking setup.

The rotating sequence is deterministically generated based on:
- The timestamp at the beginning of the current time period (UNIX seconds floored to a multiple of the period length)
- A unique service name
- A pre-shared salt value

This means that legitimate clients and servers will independently generate the same sequence each new period, while attackers cannot predict future sequences without knowing the salt nor modulo.

## How It Works (Short version)

Both the server and client independently generate the same knock sequence for a given period (can be any delay, a week like a few minutes). The server script automatically updates `/etc/knockd.conf` then reloads knockd, while the client script generates the sequence only when needed.

## Components

### knockd_rotator_client.py

A lightweight client-side tool that both generates and executes knock sequences:

- Can run on minimal environments like [Termux](https://termux.dev/) on Android
- Requires only Python 3 standard library
- Generates the same sequence that the server expects for the current period
- Supports two modes:
  - **Generate mode**: Creates the sequence string for a service
    - Usage: `./knockd_rotator_client.py generate <service_name>`
  - **Knock mode**: Performs the actual port knocking against a target host
    - Usage: `./knockd_rotator_client.py knock <host> <service_name>`
- Automatically appends "_ROTATOR" to service names if not already present

### knockd_rotator_server.py

A server-side tool that:

- Scans `/etc/knockd.conf` for sections ending with `_ROTATOR`
- Updates those sections with freshly generated sequences
- Reloads the knockd service after updating
- Can be run as a systemd timer (see `knockd_rotator.service` and timer files)
- Usage: `./knockd_rotator_server.py [--dry-run] [--config /path/to/knockd.conf]`

## Configuration

The system is configured through environment variables:

- `KNOCKD_ROTATOR_LENGTH`: Number of ports in the knock sequence (default: 10)
- `KNOCKD_ROTATOR_SALT`: The shared secret used to generate sequences (required, no default)
- `KNOCKD_ROTATOR_PORT_MODULO`: Controls TCP/UDP protocol selection:
  - When `KNOCKD_ROTATOR_PORT_MODULO = 0` (default): All knocks use TCP protocol
  - When `KNOCKD_ROTATOR_PORT_MODULO > 0`: Port modulo MODULO determines protocol (even = TCP, odd = UDP)
- `KNOCKD_ROTATOR_PERIOD_MODULO`: Controls how frequently the sequence changes, in seconds (default: 21600, which is 6 hours)

Port numbers are generated in the range 2000-65535 to avoid requiring elevated privileges on many systems, as ports below 1024 typically require root access.

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
3. Set up a systemd timer or cron job to run `knockd_rotator_server.py` at your desired frequency using the provided examples.
4. Make sure your client has the `knockd_rotator_client.py` script and the same environment variables (salt, modulos etc)

## Notes

- I am *obviously* not a security expert.
- This works fine using `ufw` in my tests.
- I don't advise using a very frequent rotation unless you don't use knockd's `start_command` and `stop_command` because if it happens between the two you might end up in a compromised state.
- The code is minimal on purpose so that you just have to copy the `knockd_rotator_client.py` file around and the env variables.
