#!/bin/bash

# Pre-commit Coverage Validation Script
# Validates test coverage before allowing commits

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-60}  # Lower threshold for pre-commit
FAST_MODE=${FAST_MODE:-true}  # Quick coverage check by default

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if cargo-tarpaulin is installed
check_tarpaulin() {
    if ! command -v cargo-tarpaulin &> /dev/null; then
        log_warning "cargo-tarpaulin not found. Installing..."
        cargo install cargo-tarpaulin
        if [ $? -ne 0 ]; then
            log_error "Failed to install cargo-tarpaulin"
            log_info "Please install manually: cargo install cargo-tarpaulin"
            exit 1
        fi
    fi
}

# Function to run quick coverage check
run_quick_coverage() {
    log_info "Running quick coverage check..."
    
    cd "${PROJECT_ROOT}"
    
    # Run tarpaulin with reduced scope for speed
    cargo tarpaulin \
        --lib \
        --timeout 60 \
        --out Stdout \
        --exclude-files "src/main.rs" \
        --exclude-files "src/bin/*" \
        --quiet \
        2>/dev/null | tee coverage_pre_commit.log
}

# Function to run comprehensive coverage check
run_comprehensive_coverage() {
    log_info "Running comprehensive coverage check..."
    
    cd "${PROJECT_ROOT}"
    
    # Run comprehensive tarpaulin analysis
    cargo tarpaulin \
        --lib \
        --tests \
        --timeout 120 \
        --out Stdout \
        --exclude-files "src/main.rs" \
        --exclude-files "src/bin/*" \
        --exclude-files "tests/common/*" \
        --ignore-panics \
        --quiet \
        2>/dev/null | tee coverage_pre_commit.log
}

# Function to extract coverage percentage
extract_coverage() {
    if [ -f "coverage_pre_commit.log" ]; then
        # Extract coverage percentage from output
        COVERAGE_PERCENT=$(grep -oE "[0-9]+\.[0-9]+% coverage" coverage_pre_commit.log | grep -oE "[0-9]+\.[0-9]+" | tail -1)
        
        if [ -n "${COVERAGE_PERCENT}" ]; then
            echo "${COVERAGE_PERCENT}"
        else
            # Fallback to extract just the number
            grep -oE "[0-9]+\.[0-9]+" coverage_pre_commit.log | tail -1
        fi
    else
        echo "0"
    fi
}

# Function to validate coverage against threshold
validate_coverage() {
    local coverage_percent=$1
    
    if [ -z "${coverage_percent}" ] || [ "${coverage_percent}" = "0" ]; then
        log_error "Could not determine coverage percentage"
        return 1
    fi
    
    # Convert to integer for comparison
    coverage_int=$(echo "${coverage_percent}" | cut -d'.' -f1)
    
    log_info "Coverage: ${coverage_percent}%"
    log_info "Threshold: ${COVERAGE_THRESHOLD}%"
    
    if [ "${coverage_int}" -ge "${COVERAGE_THRESHOLD}" ]; then
        log_success "Coverage validation PASSED (${coverage_percent}% ≥ ${COVERAGE_THRESHOLD}%)"
        return 0
    else
        log_error "Coverage validation FAILED (${coverage_percent}% < ${COVERAGE_THRESHOLD}%)"
        return 1
    fi
}

# Function to show coverage improvement suggestions
show_improvement_suggestions() {
    cat << 'EOF'

📊 Coverage Improvement Suggestions:

High Priority:
• Add tests for authentication handlers (src/handlers/auth.rs)
• Improve JWT utility test coverage (src/utils/jwt.rs)
• Test password security functions (src/utils/password.rs)
• Add database adapter tests (src/database/)

Medium Priority:
• Test cache implementations (src/cache/)
• Add middleware test coverage (src/middleware/)
• Test configuration validation (src/config/)

Quick Wins:
• Add unit tests for models (src/models/)
• Test utility functions (src/utils/)
• Add error handling tests

💡 Tips:
• Use `cargo tarpaulin --lib --out Html` for detailed coverage report
• Focus on testing critical security paths first
• Add integration tests for end-to-end scenarios
• Test error conditions and edge cases

EOF
}

# Function to check for critical untested modules
check_critical_modules() {
    log_info "Checking critical module coverage..."
    
    if [ -f "coverage_pre_commit.log" ]; then
        # Check for zero coverage in critical files
        critical_files=(
            "src/handlers/auth.rs"
            "src/utils/jwt.rs"
            "src/utils/password.rs"
            "src/middleware/rate_limit.rs"
        )
        
        critical_issues=0
        for file in "${critical_files[@]}"; do
            if grep -q "${file}: 0/" coverage_pre_commit.log; then
                log_warning "CRITICAL: No test coverage for ${file}"
                critical_issues=$((critical_issues + 1))
            fi
        done
        
        if [ ${critical_issues} -gt 0 ]; then
            log_error "Found ${critical_issues} critical modules with zero coverage"
            log_error "These security-critical modules must have test coverage before commit"
            return 1
        fi
    fi
    
    return 0
}

# Function to cleanup temporary files
cleanup() {
    if [ -f "coverage_pre_commit.log" ]; then
        rm -f coverage_pre_commit.log
    fi
}

# Main execution function
main() {
    log_info "🧪 Pre-commit Coverage Validation"
    log_info "Threshold: ${COVERAGE_THRESHOLD}%"
    log_info "Mode: $([ "${FAST_MODE}" = "true" ] && echo "Fast" || echo "Comprehensive")"
    
    # Change to project root
    cd "${PROJECT_ROOT}"
    
    # Cleanup on exit
    trap cleanup EXIT
    
    # Check prerequisites
    check_tarpaulin
    
    # Run coverage analysis
    if [ "${FAST_MODE}" = "true" ]; then
        run_quick_coverage
    else
        run_comprehensive_coverage
    fi
    
    # Extract and validate coverage
    coverage_percent=$(extract_coverage)
    
    if validate_coverage "${coverage_percent}"; then
        # Check critical modules even if overall coverage passes
        if check_critical_modules; then
            log_success "✅ Coverage validation completed successfully!"
            
            # Record coverage for trend tracking
            if [ -f "${SCRIPT_DIR}/coverage-trends.py" ]; then
                python3 "${SCRIPT_DIR}/coverage-trends.py" --record coverage_pre_commit.log 2>/dev/null || true
            fi
            
            exit 0
        else
            log_error "❌ Critical module coverage issues detected"
            show_improvement_suggestions
            exit 1
        fi
    else
        log_error "❌ Coverage below minimum threshold"
        check_critical_modules || true  # Show critical issues but don't exit early
        show_improvement_suggestions
        
        # Allow override with environment variable
        if [ "${COVERAGE_OVERRIDE:-false}" = "true" ]; then
            log_warning "⚠️  Coverage check overridden by COVERAGE_OVERRIDE=true"
            exit 0
        fi
        
        exit 1
    fi
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fast)
            FAST_MODE=true
            shift
            ;;
        --comprehensive)
            FAST_MODE=false
            shift
            ;;
        --threshold)
            COVERAGE_THRESHOLD="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --fast              Run quick coverage check (default)"
            echo "  --comprehensive     Run comprehensive coverage check"
            echo "  --threshold NUM     Set coverage threshold (default: 60)"
            echo "  --help              Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  COVERAGE_THRESHOLD  Coverage threshold percentage"
            echo "  FAST_MODE          Enable/disable fast mode (true/false)"
            echo "  COVERAGE_OVERRIDE  Override coverage check (true/false)"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Execute main function
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi