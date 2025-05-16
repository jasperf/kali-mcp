#!/bin/bash
# Script to run tests and verify code quality

set -e  # Exit on error

echo "===== Setting up virtual environment ====="
python -m venv .venv
source .venv/bin/activate

echo "===== Installing dependencies ====="
pip install -e ".[dev]"

echo "===== Running type checking ====="
pyright

echo "===== Running linting ====="
ruff check .

echo "===== Running tests ====="
pytest

echo "===== All checks passed! ====="