#!/bin/bash
set -e

echo "Running backend linting (Ruff)..."
ruff check backend/

echo "Running backend type checking (Mypy)..."
mypy backend/

echo "Running frontend linting (ESLint)..."
cd frontend && npm run lint

echo "All checks passed!"
