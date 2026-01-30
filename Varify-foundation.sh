#!/bin/bash
# verify-foundation.sh

echo "=== GitDigital Foundation Verification ==="

echo "1. Checking Anchor installation..."
anchor --version || echo "❌ Anchor not installed"

echo "2. Checking Solana CLI..."
solana --version || echo "❌ Solana CLI not installed"

echo "3. Checking program build..."
if [ -d "programs/founder_loan_program" ]; then
    cd programs/founder_loan_program
    cargo check 2>&1 | head -20
    cd ../..
else
    echo "❌ Program directory not found"
fi

echo "4. Checking TypeScript bindings..."
if [ -f "target/types/founder_loan_program.ts" ]; then
    echo "✅ TypeScript bindings generated"
else
    echo "❌ TypeScript bindings missing (run anchor build)"
fi

echo "5. Checking program ID..."
grep "declare_id" programs/founder_loan_program/src/lib.rs

echo "6. Checking test files..."
find . -name "*.test.ts" -o -name "*test.rs" | head -5

echo "7. Git status..."
git status --short

echo "=== Verification Complete ==="

