# Honeypot

A small Python honeypot that listens on a fake SSH port and logs everyone who connects. Built as a learning project for networking and cybersecurity.

## Status
- [x] Stage 1: TCP server, fake SSH banner, event logging
- [ ] Stage 2: Multiple clients at once (threading)
- [ ] Stage 3: Fake login prompt that captures credentials
- [ ] Stage 4: Threat score per IP
- [ ] Stage 5: Live terminal dashboard

## Project structure
```
honeypot/
├── honeypot/
│   ├── config.py    # port, banner, log path
│   ├── server.py    # listens and accepts connections
│   ├── handler.py   # fake banner and per-client behaviour
│   └── logger.py    # writes timestamped events to a file
├── logs/            # runtime logs (not tracked by git)
├── tests/
└── main.py          # entry point
```

## Run
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 main.py
```

## Try it
In a second terminal:
```bash
nc 127.0.0.1 2222
cat logs/honeypot.log
```

## Safety
- Binds to `127.0.0.1` by default, so only your own machine can connect.
- Only run this on machines and networks you own.
- Logs contain visitor data and are excluded from git.