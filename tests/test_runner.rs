//! # Comprehensive Test Runner
//!
//! Unified test runner for all integration tests. Provides comprehensive
//! test execution, reporting, and coverage analysis for the authentication service.

use anyhow::Result;
use std::process::Command;
use std::time::{Duration, Instant};

/// Test runner configuration
#[derive(Debug, Clone)]
pub struct TestRunnerConfig {
    pub run_unit_tests: bool,
    pub run_integration_tests: bool,
    pub run_load_tests: bool,
    pub run_container_tests: bool,
    pub generate_coverage: bool,
    pub parallel_execution: bool,
    pub output_format: OutputFormat,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Console,
    Json,
    Junit,
    Html,
}

impl Default for TestRunnerConfig {
    fn default() -> Self {
        Self {
            run_unit_tests: true,
            run_integration_tests: true,
            run_load_tests: false,      // Load tests are expensive
            run_container_tests: false, // Requires Docker
            generate_coverage: true,
            parallel_execution: true,
            output_format: OutputFormat::Console,
            timeout: Duration::from_secs(600), // 10 minutes
        }
    }
}

/// Test execution results
#[derive(Debug)]
pub struct TestResults {
    pub unit_tests: Option<TestSuiteResult>,
    pub integration_tests: Option<TestSuiteResult>,
    pub load_tests: Option<TestSuiteResult>,
    pub container_tests: Option<TestSuiteResult>,
    pub coverage: Option<CoverageResult>,
    pub total_duration: Duration,
}

#[derive(Debug)]
pub struct TestSuiteResult {
    pub name: String,
    pub passed: usize,
    pub failed: usize,
    pub ignored: usize,
    pub duration: Duration,
    pub failures: Vec<String>,
}

#[derive(Debug)]
pub struct CoverageResult {
    pub line_coverage: f64,
    pub branch_coverage: f64,
    pub function_coverage: f64,
    pub report_path: Option<String>,
}

/// Comprehensive test runner
pub struct TestRunner {
    config: TestRunnerConfig,
}

impl TestRunner {
    pub fn new(config: TestRunnerConfig) -> Self {
        Self { config }
    }

    /// Run all configured tests
    pub async fn run_all_tests(&self) -> Result<TestResults> {
        println!("🚀 Starting comprehensive test execution");
        let start_time = Instant::now();

        let mut results = TestResults {
            unit_tests: None,
            integration_tests: None,
            load_tests: None,
            container_tests: None,
            coverage: None,
            total_duration: Duration::from_secs(0),
        };

        // Check prerequisites
        self.check_prerequisites().await?;

        // Run unit tests
        if self.config.run_unit_tests {
            println!("🧪 Running unit tests...");
            results.unit_tests = Some(self.run_unit_tests().await?);
        }

        // Run integration tests
        if self.config.run_integration_tests {
            println!("🔗 Running integration tests...");
            results.integration_tests = Some(self.run_integration_tests().await?);
        }

        // Run load tests
        if self.config.run_load_tests {
            println!("🚀 Running load tests...");
            results.load_tests = Some(self.run_load_tests().await?);
        }

        // Run container tests
        if self.config.run_container_tests {
            println!("🐳 Running container tests...");
            results.container_tests = Some(self.run_container_tests().await?);
        }

        // Generate coverage report
        if self.config.generate_coverage {
            println!("📊 Generating coverage report...");
            results.coverage = Some(self.generate_coverage().await?);
        }

        results.total_duration = start_time.elapsed();

        // Print summary
        self.print_test_summary(&results);

        Ok(results)
    }

    /// Check test prerequisites
    async fn check_prerequisites(&self) -> Result<()> {
        println!("🔍 Checking test prerequisites...");

        // Check if cargo is available
        let cargo_version = Command::new("cargo").args(&["--version"]).output()?;

        if !cargo_version.status.success() {
            return Err(anyhow::anyhow!("Cargo is not available"));
        }

        // Check if Docker is available (for container tests)
        if self.config.run_container_tests {
            let docker_version = Command::new("docker").args(&["--version"]).output();

            if docker_version.is_err() || !docker_version.unwrap().status.success() {
                println!("⚠️ Docker not available, container tests will be skipped");
            }
        }

        // Check if tarpaulin is available (for coverage)
        if self.config.generate_coverage {
            let tarpaulin_check = Command::new("cargo")
                .args(&["tarpaulin", "--version"])
                .output();

            if tarpaulin_check.is_err() || !tarpaulin_check.unwrap().status.success() {
                println!("⚠️ cargo-tarpaulin not installed, installing...");
                let install_output = Command::new("cargo")
                    .args(&["install", "cargo-tarpaulin"])
                    .output()?;

                if !install_output.status.success() {
                    println!("⚠️ Failed to install cargo-tarpaulin, coverage will be skipped");
                }
            }
        }

        println!("✅ Prerequisites checked");
        Ok(())
    }

    /// Run unit tests
    async fn run_unit_tests(&self) -> Result<TestSuiteResult> {
        let start_time = Instant::now();

        let mut cmd = Command::new("cargo");
        cmd.args(&["test", "--lib", "--bins"]);

        if self.config.parallel_execution {
            cmd.args(&["--", "--test-threads", "4"]);
        }

        let output = cmd.output()?;
        let duration = start_time.elapsed();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let (passed, failed, ignored) = self.parse_test_output(&stdout);
        let failures = self.extract_failures(&stderr);

        Ok(TestSuiteResult {
            name: "Unit Tests".to_string(),
            passed,
            failed,
            ignored,
            duration,
            failures,
        })
    }

    /// Run integration tests
    async fn run_integration_tests(&self) -> Result<TestSuiteResult> {
        let start_time = Instant::now();

        let mut cmd = Command::new("cargo");
        cmd.args(&["test", "--test", "*", "--features", "integration-tests"]);

        if self.config.parallel_execution {
            cmd.args(&["--", "--test-threads", "2"]); // Fewer threads for integration tests
        }

        let output = cmd.output()?;
        let duration = start_time.elapsed();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let (passed, failed, ignored) = self.parse_test_output(&stdout);
        let failures = self.extract_failures(&stderr);

        Ok(TestSuiteResult {
            name: "Integration Tests".to_string(),
            passed,
            failed,
            ignored,
            duration,
            failures,
        })
    }

    /// Run load tests
    async fn run_load_tests(&self) -> Result<TestSuiteResult> {
        let start_time = Instant::now();

        let mut cmd = Command::new("cargo");
        cmd.args(&[
            "test",
            "load_tests",
            "--features",
            "integration-tests,load-tests",
        ]);
        cmd.args(&["--", "--test-threads", "1"]); // Load tests should run sequentially

        let output = cmd.output()?;
        let duration = start_time.elapsed();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let (passed, failed, ignored) = self.parse_test_output(&stdout);
        let failures = self.extract_failures(&stderr);

        Ok(TestSuiteResult {
            name: "Load Tests".to_string(),
            passed,
            failed,
            ignored,
            duration,
            failures,
        })
    }

    /// Run container tests
    async fn run_container_tests(&self) -> Result<TestSuiteResult> {
        let start_time = Instant::now();

        let mut cmd = Command::new("cargo");
        cmd.args(&[
            "test",
            "test_containers",
            "--features",
            "integration-tests,test-containers",
        ]);
        cmd.args(&["--", "--test-threads", "1"]); // Container tests should run sequentially

        let output = cmd.output()?;
        let duration = start_time.elapsed();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let (passed, failed, ignored) = self.parse_test_output(&stdout);
        let failures = self.extract_failures(&stderr);

        Ok(TestSuiteResult {
            name: "Container Tests".to_string(),
            passed,
            failed,
            ignored,
            duration,
            failures,
        })
    }

    /// Generate coverage report
    async fn generate_coverage(&self) -> Result<CoverageResult> {
        let mut cmd = Command::new("cargo");
        cmd.args(&[
            "tarpaulin",
            "--verbose",
            "--all-features",
            "--workspace",
            "--timeout",
            "300",
            "--exclude-files",
            "target/*",
            "--exclude-files",
            "tests/*",
            "--exclude-files",
            "benches/*",
            "--out",
            "Html",
            "--out",
            "Xml",
        ]);

        let output = cmd.output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Coverage generation failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse coverage from tarpaulin output
        let line_coverage = self.extract_coverage_percentage(&stdout, "Coverage Results:");

        Ok(CoverageResult {
            line_coverage,
            branch_coverage: 0.0, // Tarpaulin doesn't provide branch coverage by default
            function_coverage: 0.0, // Would need additional tooling
            report_path: Some("tarpaulin-report.html".to_string()),
        })
    }

    /// Parse test output to extract counts
    fn parse_test_output(&self, output: &str) -> (usize, usize, usize) {
        let mut passed = 0;
        let mut failed = 0;
        let mut ignored = 0;

        for line in output.lines() {
            if line.contains("test result:") {
                // Look for pattern like "test result: ok. 42 passed; 0 failed; 0 ignored"
                if let Some(stats_part) = line.split("test result:").nth(1) {
                    for part in stats_part.split(';') {
                        let part = part.trim();
                        if part.contains("passed") {
                            if let Some(num_str) = part.split_whitespace().next() {
                                passed = num_str.parse().unwrap_or(0);
                            }
                        } else if part.contains("failed") {
                            if let Some(num_str) = part.split_whitespace().next() {
                                failed = num_str.parse().unwrap_or(0);
                            }
                        } else if part.contains("ignored") {
                            if let Some(num_str) = part.split_whitespace().next() {
                                ignored = num_str.parse().unwrap_or(0);
                            }
                        }
                    }
                }
                break;
            }
        }

        (passed, failed, ignored)
    }

    /// Extract failure messages from output
    fn extract_failures(&self, output: &str) -> Vec<String> {
        let mut failures = Vec::new();
        let mut in_failure = false;
        let mut current_failure = String::new();

        for line in output.lines() {
            if line.starts_with("---- ") && line.contains(" stdout ----") {
                if !current_failure.is_empty() {
                    failures.push(current_failure.clone());
                    current_failure.clear();
                }
                in_failure = true;
                current_failure.push_str(line);
                current_failure.push('\n');
            } else if in_failure {
                current_failure.push_str(line);
                current_failure.push('\n');

                if line.is_empty() && current_failure.len() > 100 {
                    // End of failure block
                    in_failure = false;
                }
            }
        }

        if !current_failure.is_empty() {
            failures.push(current_failure);
        }

        failures
    }

    /// Extract coverage percentage from tarpaulin output
    fn extract_coverage_percentage(&self, output: &str, marker: &str) -> f64 {
        for line in output.lines() {
            if line.contains(marker) {
                // Look for percentage in the line
                if let Some(percent_pos) = line.find('%') {
                    let before_percent = &line[..percent_pos];
                    if let Some(start) = before_percent.rfind(' ') {
                        let percent_str = &before_percent[start + 1..];
                        if let Ok(percentage) = percent_str.parse::<f64>() {
                            return percentage;
                        }
                    }
                }
            }
        }
        0.0
    }

    /// Print comprehensive test summary
    fn print_test_summary(&self, results: &TestResults) {
        let separator = "=".repeat(80);
        println!("\n{}", separator);
        println!("📊 COMPREHENSIVE TEST RESULTS SUMMARY");
        println!("{}", separator);

        let mut total_passed = 0;
        let mut total_failed = 0;
        let mut total_ignored = 0;

        // Unit Tests
        if let Some(unit) = &results.unit_tests {
            self.print_suite_summary(unit);
            total_passed += unit.passed;
            total_failed += unit.failed;
            total_ignored += unit.ignored;
        }

        // Integration Tests
        if let Some(integration) = &results.integration_tests {
            self.print_suite_summary(integration);
            total_passed += integration.passed;
            total_failed += integration.failed;
            total_ignored += integration.ignored;
        }

        // Load Tests
        if let Some(load) = &results.load_tests {
            self.print_suite_summary(load);
            total_passed += load.passed;
            total_failed += load.failed;
            total_ignored += load.ignored;
        }

        // Container Tests
        if let Some(container) = &results.container_tests {
            self.print_suite_summary(container);
            total_passed += container.passed;
            total_failed += container.failed;
            total_ignored += container.ignored;
        }

        // Coverage
        if let Some(coverage) = &results.coverage {
            println!("\n📈 CODE COVERAGE:");
            println!("  Line Coverage: {:.1}%", coverage.line_coverage);
            if let Some(report_path) = &coverage.report_path {
                println!("  Report: {}", report_path);
            }
        }

        // Overall Summary
        println!("\n🎯 OVERALL RESULTS:");
        println!(
            "  Total Tests: {}",
            total_passed + total_failed + total_ignored
        );
        println!(
            "  ✅ Passed: {} ({:.1}%)",
            total_passed,
            (total_passed as f64 / (total_passed + total_failed) as f64) * 100.0
        );
        println!(
            "  ❌ Failed: {} ({:.1}%)",
            total_failed,
            (total_failed as f64 / (total_passed + total_failed) as f64) * 100.0
        );
        println!("  ⏭️ Ignored: {}", total_ignored);
        println!(
            "  ⏱️ Total Duration: {:.2}s",
            results.total_duration.as_secs_f64()
        );

        // Success/Failure determination
        if total_failed == 0 {
            println!("\n🎉 ALL TESTS PASSED! 🎉");
        } else {
            println!("\n💥 {} TESTS FAILED 💥", total_failed);

            // Print failure details
            self.print_failure_details(results);
        }

        println!("{}", separator);
    }

    fn print_suite_summary(&self, suite: &TestSuiteResult) {
        println!("\n🧪 {}:", suite.name);
        println!("  Passed: {}", suite.passed);
        println!("  Failed: {}", suite.failed);
        println!("  Ignored: {}", suite.ignored);
        println!("  Duration: {:.2}s", suite.duration.as_secs_f64());

        if suite.failed > 0 {
            println!("  ❌ {} failures detected", suite.failed);
        } else {
            println!("  ✅ All tests passed");
        }
    }

    fn print_failure_details(&self, results: &TestResults) {
        println!("\n💥 FAILURE DETAILS:");

        let all_suites = [
            &results.unit_tests,
            &results.integration_tests,
            &results.load_tests,
            &results.container_tests,
        ];
        for suite_option in all_suites.iter() {
            if let Some(suite) = suite_option {
                if !suite.failures.is_empty() {
                    println!("\n❌ {} Failures:", suite.name);
                    for (i, failure) in suite.failures.iter().enumerate() {
                        println!(
                            "  {}. {}",
                            i + 1,
                            failure.lines().next().unwrap_or("Unknown failure")
                        );
                    }
                }
            }
        }
    }
}

/// Run comprehensive tests with default configuration
pub async fn run_comprehensive_tests() -> Result<TestResults> {
    let config = TestRunnerConfig::default();
    let runner = TestRunner::new(config);
    runner.run_all_tests().await
}

/// Run only integration tests
pub async fn run_integration_tests_only() -> Result<TestResults> {
    let config = TestRunnerConfig {
        run_unit_tests: false,
        run_integration_tests: true,
        run_load_tests: false,
        run_container_tests: false,
        generate_coverage: false,
        ..TestRunnerConfig::default()
    };
    let runner = TestRunner::new(config);
    runner.run_all_tests().await
}

/// Run performance tests only
pub async fn run_performance_tests_only() -> Result<TestResults> {
    let config = TestRunnerConfig {
        run_unit_tests: false,
        run_integration_tests: false,
        run_load_tests: true,
        run_container_tests: false,
        generate_coverage: false,
        ..TestRunnerConfig::default()
    };
    let runner = TestRunner::new(config);
    runner.run_all_tests().await
}

#[tokio::test]
async fn test_runner_smoke_test() -> Result<()> {
    // Basic smoke test to ensure the test runner works
    let config = TestRunnerConfig {
        run_unit_tests: true,
        run_integration_tests: false,
        run_load_tests: false,
        run_container_tests: false,
        generate_coverage: false,
        timeout: Duration::from_secs(30),
        ..TestRunnerConfig::default()
    };

    let runner = TestRunner::new(config);
    let results = runner.run_all_tests().await?;

    // Verify that we got some results
    assert!(results.unit_tests.is_some());

    Ok(())
}
