#!/bin/bash

# Rust Auth Service - Test Coverage Analysis Script
# Comprehensive coverage reporting with multiple output formats

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COVERAGE_DIR="${PROJECT_ROOT}/coverage"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

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

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if cargo-tarpaulin is installed
    if ! command -v cargo-tarpaulin &> /dev/null; then
        log_warning "cargo-tarpaulin not found. Installing..."
        cargo install cargo-tarpaulin
    fi
    
    # Check if jq is installed for JSON processing
    if ! command -v jq &> /dev/null; then
        log_warning "jq not found. Some JSON processing features will be limited."
    fi
    
    log_success "Prerequisites check complete"
}

# Function to clean previous coverage data
clean_coverage() {
    log_info "Cleaning previous coverage data..."
    
    if [ -d "${COVERAGE_DIR}" ]; then
        rm -rf "${COVERAGE_DIR}"
    fi
    
    mkdir -p "${COVERAGE_DIR}"
    mkdir -p "${COVERAGE_DIR}/reports"
    mkdir -p "${COVERAGE_DIR}/history"
    
    log_success "Coverage directory prepared"
}

# Function to run basic coverage
run_basic_coverage() {
    log_info "Running basic coverage analysis..."
    
    cd "${PROJECT_ROOT}"
    
    # Run tarpaulin with basic configuration
    cargo tarpaulin \
        --lib \
        --verbose \
        --timeout 120 \
        --out Html,Xml,Json,Stdout \
        --output-dir "${COVERAGE_DIR}" \
        --exclude-files "src/main.rs" \
        --exclude-files "src/bin/*" \
        2>&1 | tee "${COVERAGE_DIR}/basic_coverage.log"
    
    log_success "Basic coverage analysis complete"
}

# Function to run comprehensive coverage
run_comprehensive_coverage() {
    log_info "Running comprehensive coverage analysis..."
    
    cd "${PROJECT_ROOT}"
    
    # Run with all features and comprehensive reporting
    cargo tarpaulin \
        --lib \
        --tests \
        --verbose \
        --timeout 180 \
        --out Html,Xml,Json,Stdout \
        --output-dir "${COVERAGE_DIR}/reports" \
        --exclude-files "src/main.rs" \
        --exclude-files "src/bin/*" \
        --exclude-files "tests/common/*" \
        --ignore-panics \
        --follow-exec \
        2>&1 | tee "${COVERAGE_DIR}/comprehensive_coverage.log"
    
    log_success "Comprehensive coverage analysis complete"
}

# Function to generate coverage by module
generate_module_coverage() {
    log_info "Generating module-specific coverage reports..."
    
    # Define critical modules for targeted analysis
    modules=(
        "src/handlers/auth.rs"
        "src/utils/jwt.rs"
        "src/utils/password.rs"
        "src/models/user.rs"
        "src/database/mongodb.rs"
        "src/cache/redis_cache.rs"
        "src/cache/memory_cache.rs"
        "src/middleware/rate_limit.rs"
        "src/config/validator.rs"
        "src/mfa/"
    )
    
    for module in "${modules[@]}"; do
        if [ -e "${PROJECT_ROOT}/${module}" ]; then
            log_info "Analyzing coverage for ${module}..."
            
            # Create module-specific report
            module_name=$(basename "${module}" .rs)
            cargo tarpaulin \
                --lib \
                --verbose \
                --timeout 60 \
                --out Html \
                --output-dir "${COVERAGE_DIR}/modules/${module_name}" \
                --include-tests \
                --packages rust-auth-service \
                2>&1 | tee "${COVERAGE_DIR}/modules/${module_name}/coverage.log" || true
        fi
    done
    
    log_success "Module coverage reports generated"
}

# Function to analyze coverage trends
analyze_coverage_trends() {
    log_info "Analyzing coverage trends..."
    
    # Create history entry
    HISTORY_FILE="${COVERAGE_DIR}/history/coverage_${TIMESTAMP}.json"
    
    if [ -f "${COVERAGE_DIR}/cobertura.xml" ]; then
        # Extract coverage percentage from XML
        COVERAGE_PERCENT=$(grep -o 'line-rate="[0-9.]*"' "${COVERAGE_DIR}/cobertura.xml" | head -1 | grep -o '[0-9.]*' || echo "0")
        
        # Create history entry
        cat > "${HISTORY_FILE}" << EOF
{
  "timestamp": "${TIMESTAMP}",
  "date": "$(date -Iseconds)",
  "coverage_percent": ${COVERAGE_PERCENT:-0},
  "total_lines": $(grep -o 'lines-covered="[0-9]*"' "${COVERAGE_DIR}/cobertura.xml" | head -1 | grep -o '[0-9]*' || echo "0"),
  "covered_lines": $(grep -o 'lines-valid="[0-9]*"' "${COVERAGE_DIR}/cobertura.xml" | head -1 | grep -o '[0-9]*' || echo "0"),
  "branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')",
  "commit": "$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
}
EOF
        
        log_success "Coverage trend data recorded: ${COVERAGE_PERCENT}%"
    else
        log_warning "No XML coverage data found for trend analysis"
    fi
}

# Function to generate coverage summary
generate_coverage_summary() {
    log_info "Generating coverage summary..."
    
    SUMMARY_FILE="${COVERAGE_DIR}/coverage_summary.md"
    
    cat > "${SUMMARY_FILE}" << 'EOF'
# Test Coverage Summary

## Overall Coverage Statistics

EOF
    
    # Add coverage percentage from log
    if [ -f "${COVERAGE_DIR}/comprehensive_coverage.log" ]; then
        COVERAGE_LINE=$(grep -E "^[0-9]+\.[0-9]+% coverage" "${COVERAGE_DIR}/comprehensive_coverage.log" | tail -1 || echo "Coverage data not available")
        echo "- **Total Coverage**: ${COVERAGE_LINE}" >> "${SUMMARY_FILE}"
    fi
    
    # Add timestamp
    echo "- **Generated**: $(date)" >> "${SUMMARY_FILE}"
    echo "- **Git Branch**: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')" >> "${SUMMARY_FILE}"
    echo "- **Git Commit**: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" >> "${SUMMARY_FILE}"
    
    cat >> "${SUMMARY_FILE}" << 'EOF'

## Coverage by Module

| Module | Coverage | Priority | Target |
|--------|----------|----------|---------|
| Authentication | TBD | Critical | 85% |
| JWT Utils | TBD | Critical | 90% |
| Password Utils | TBD | Critical | 85% |
| User Models | TBD | Critical | 90% |
| Database Layer | TBD | High | 75% |
| Cache Layer | TBD | High | 70% |
| Rate Limiting | TBD | Critical | 85% |
| MFA Components | TBD | High | 80% |
| Email Services | TBD | Medium | 60% |
| Config Validation | TBD | High | 75% |

## Reports Available

- [HTML Report](./tarpaulin-report.html) - Interactive coverage visualization
- [XML Report](./cobertura.xml) - CI/CD integration format
- [JSON Report](./tarpaulin-report.json) - Programmatic analysis

## Coverage Improvement Recommendations

### High Priority (Security Critical)
1. **Authentication Handlers** - Increase coverage for login/registration flows
2. **JWT Token Management** - Ensure all token scenarios are tested
3. **Password Security** - Test all hashing and validation paths
4. **Rate Limiting** - Verify all rate limiting scenarios

### Medium Priority (Core Functionality)
1. **Database Adapters** - Add tests for all database operations
2. **Cache Providers** - Test cache failover and error scenarios
3. **User Management** - Cover user lifecycle operations
4. **Email Integration** - Test email provider fallbacks

### Lower Priority (Infrastructure)
1. **Configuration Management** - Test configuration validation
2. **Observability** - Add metrics and logging tests
3. **Migration System** - Test database migration scenarios

## Next Steps

1. **Address Critical Gaps**: Focus on security-critical modules first
2. **Integration Testing**: Expand integration test coverage
3. **Error Scenarios**: Test failure and edge cases
4. **Performance Tests**: Add performance regression tests
5. **Documentation**: Update code documentation with examples

EOF
    
    log_success "Coverage summary generated: ${SUMMARY_FILE}"
}

# Function to check coverage thresholds
check_coverage_thresholds() {
    log_info "Checking coverage thresholds..."
    
    if [ -f "${COVERAGE_DIR}/comprehensive_coverage.log" ]; then
        # Extract coverage percentage
        COVERAGE_PERCENT=$(grep -oE "[0-9]+\.[0-9]+% coverage" "${COVERAGE_DIR}/comprehensive_coverage.log" | grep -oE "[0-9]+\.[0-9]+" | tail -1)
        
        if [ -n "${COVERAGE_PERCENT}" ]; then
            # Convert to integer for comparison
            COVERAGE_INT=$(echo "${COVERAGE_PERCENT}" | cut -d'.' -f1)
            
            # Define thresholds
            MINIMUM_THRESHOLD=70
            TARGET_THRESHOLD=80
            EXCELLENT_THRESHOLD=90
            
            if [ "${COVERAGE_INT}" -ge "${EXCELLENT_THRESHOLD}" ]; then
                log_success "Excellent coverage: ${COVERAGE_PERCENT}% (≥${EXCELLENT_THRESHOLD}%)"
                return 0
            elif [ "${COVERAGE_INT}" -ge "${TARGET_THRESHOLD}" ]; then
                log_success "Good coverage: ${COVERAGE_PERCENT}% (≥${TARGET_THRESHOLD}%)"
                return 0
            elif [ "${COVERAGE_INT}" -ge "${MINIMUM_THRESHOLD}" ]; then
                log_warning "Acceptable coverage: ${COVERAGE_PERCENT}% (≥${MINIMUM_THRESHOLD}%)"
                return 0
            else
                log_error "Coverage below minimum threshold: ${COVERAGE_PERCENT}% (<${MINIMUM_THRESHOLD}%)"
                return 1
            fi
        else
            log_error "Could not extract coverage percentage from logs"
            return 1
        fi
    else
        log_error "Coverage log file not found"
        return 1
    fi
}

# Function to upload coverage to external services
upload_coverage() {
    log_info "Preparing coverage for upload..."
    
    # Check if we're in CI environment
    if [ "${CI:-false}" = "true" ]; then
        log_info "CI environment detected, uploading coverage..."
        
        # Upload to Codecov if token is available
        if [ -n "${CODECOV_TOKEN:-}" ]; then
            if command -v codecov &> /dev/null; then
                codecov -f "${COVERAGE_DIR}/cobertura.xml" -t "${CODECOV_TOKEN}"
                log_success "Coverage uploaded to Codecov"
            else
                log_warning "codecov CLI not found, skipping upload"
            fi
        fi
        
        # Upload to Coveralls if token is available
        if [ -n "${COVERALLS_TOKEN:-}" ]; then
            log_info "Coveralls upload not implemented yet"
        fi
    else
        log_info "Not in CI environment, skipping coverage upload"
    fi
}

# Main execution function
main() {
    log_info "Starting comprehensive test coverage analysis..."
    log_info "Project: Rust Auth Service"
    log_info "Timestamp: ${TIMESTAMP}"
    
    # Change to project root
    cd "${PROJECT_ROOT}"
    
    # Execute coverage pipeline
    check_prerequisites
    clean_coverage
    run_basic_coverage
    run_comprehensive_coverage
    generate_module_coverage
    analyze_coverage_trends
    generate_coverage_summary
    
    # Check thresholds and upload
    if check_coverage_thresholds; then
        upload_coverage
        log_success "Coverage analysis completed successfully!"
        exit 0
    else
        log_error "Coverage analysis completed with threshold violations!"
        exit 1
    fi
}

# Script entry point
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi