#!/bin/sh
# Fix ownership of the data volume (runs as root, then drops to scanner)
chown -R scanner:scanner /app/data
exec gosu scanner "$@"
