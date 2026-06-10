#!/bin/bash
# Quick setup script for fraud detection pipeline

set -e

echo "======================================"
echo "Fraud Detection Pipeline - Quick Setup"
echo "======================================"

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "✓ Creating virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate || . venv/Scripts/activate

# Install dependencies
echo "✓ Installing dependencies..."
pip install -q -r requirements.txt

# Verify data directory
if [ ! -f "data/traffic.jsonl" ]; then
    echo "✗ Error: data/traffic.jsonl not found"
    exit 1
fi
echo "✓ Traffic log found: $(wc -l < data/traffic.jsonl) lines"

# Run tests
echo ""
echo "======================================"
echo "Running Unit Tests"
echo "======================================"
python -m pytest tests/ -v --tb=short 2>&1 | head -50

# Show rules summary
echo ""
echo "======================================"
echo "Loaded Detection Rules"
echo "======================================"
python -c "
import sys
sys.path.insert(0, '.')
from engine.rule_engine import RuleEngine
engine = RuleEngine(rules_dir='rules')
summary = engine.get_rules_summary()
print(f\"Total rules: {summary['total_rules']}\")
print(f\"Enabled: {summary['enabled_rules']}\")
for rule in summary['rules'][:5]:
    print(f\"  - {rule['id']}: weight={rule['weight']} ({rule['severity']})\")
"

echo ""
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo ""
echo "To run the pipeline:"
echo "  python main.py data/traffic.jsonl data/decisions.jsonl"
echo ""
