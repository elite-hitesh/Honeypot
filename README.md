# Honeypot
A small Python honeypot that listens on a fake SSH port and logs visitors.

## Run
    python3 main.py

## Test
    nc 127.0.0.1 2222
    cat logs/honeypot.log

Only run this on machines and networks you own.