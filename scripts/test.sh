#!/bin/bash
set -e

echo "Running backend tests..."
pytest backend/tests/ "$@"
