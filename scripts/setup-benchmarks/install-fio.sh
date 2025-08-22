#!/usr/bin/env bash
set -e

FIO_REPO="https://github.com/axboe/fio.git"
BENCH_DIR="${BENCHMARK_DIR:-$HOME/kernmlops-benchmark}"
FIO_DIR="$BENCH_DIR/fio"

if [ -d "$FIO_DIR/bin/fio" ]; then
    echo "Fio already installed at $FIO_DIR"
    exit 0
fi

echo "Cloning Fio into $FIO_DIR..."
git clone "$FIO_REPO" "$FIO_DIR"
pushd "$FIO_DIR" >/dev/null

echo "Configuring & building Fio..."
./configure --prefix="$FIO_DIR"
make -j"$(nproc)"
make install

popd >/dev/null
echo "Fio installation complete."
