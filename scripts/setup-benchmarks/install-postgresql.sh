#!/bin/bash

# Define variables first
YCSB_BENCHMARK_NAME="ycsb"
BENCHMARK_DIR_NAME="kernmlops-benchmark"
BENCHMARK_DIR="${BENCHMARK_DIR:-$HOME/$BENCHMARK_DIR_NAME}"

echo "Setting up PostgreSQL benchmark..."

# Install PostgreSQL server if not already installed
if ! command -v postgres &>/dev/null; then
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            apt-get update
            apt-get install -y postgresql postgresql-contrib
        elif [ -f /etc/redhat-release ]; then
            dnf install -y postgresql postgresql-server postgresql-contrib
        fi
    else
        echo "Unsupported operating system"
        exit 1
    fi
fi

# Create PostgreSQL data directory for benchmark (separate from system)
POSTGRESQL_DATA_DIR="${BENCHMARK_DIR}/postgresql"
if [ -d "$POSTGRESQL_DATA_DIR" ]; then
    echo "Directory $POSTGRESQL_DATA_DIR already exists."
else
    mkdir -p "$POSTGRESQL_DATA_DIR/data"
    # Make sure the user who will run the container can access this
    chown -R $SUDO_USER:$SUDO_USER "$POSTGRESQL_DATA_DIR" 2>/dev/null || true
fi

# Create PostgreSQL configuration for the benchmark
cat >"${POSTGRESQL_DATA_DIR}/postgresql.conf" <<EOF
port = 5433
unix_socket_directories = '/tmp'
listen_addresses = 'localhost'
max_connections = 100
shared_buffers = 128MB
log_statement = 'none'
log_min_messages = warning
EOF

# Start the system PostgreSQL service to create database and user
systemctl start postgresql || service postgresql start

# Wait a moment for PostgreSQL to start
sleep 3

# Create database and user for YCSB using system PostgreSQL
sudo -u postgres createdb ycsb 2>/dev/null || echo "Database ycsb might already exist"
sudo -u postgres psql -c "CREATE USER ycsbuser WITH PASSWORD 'password';" 2>/dev/null || echo "User ycsbuser might already exist"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ycsb TO ycsbuser;"
sudo -u postgres psql -c "ALTER USER ycsbuser CREATEDB;"

# Make sure permissions are correct for the benchmark directory
chown -R $SUDO_USER:$SUDO_USER "$BENCHMARK_DIR" 2>/dev/null || true

echo "PostgreSQL benchmark setup complete"
echo "System PostgreSQL is running and configured for YCSB"
echo "Benchmark directory: $POSTGRESQL_DATA_DIR"
