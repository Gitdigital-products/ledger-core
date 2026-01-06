#!/bin/bash

set -e

# Deployment script for GitDigital Ledger Core

echo "Starting deployment of GitDigital Ledger Core..."

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Build the application
echo "Building application..."
cargo build --release

# Run database migrations
echo "Running database migrations..."
psql $DATABASE_URL -f migrations/001_initial_schema.sql

# Set up monitoring
echo "Setting up monitoring..."
cp config/prometheus.yml /etc/prometheus/

# Restart services
echo "Restarting services..."
systemctl restart gitdigital-ledger

echo "Deployment completed successfully!"
