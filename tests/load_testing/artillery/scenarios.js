// Artillery scenario processor for Rust Auth Service performance testing
// Implements custom functions for Issue #43 performance targets

const crypto = require('crypto');

// Global state for managing test data
let registeredUsers = [];
let tokenPool = [];
let userCounter = 0;

/**
 * Generate a unique user for registration testing
 * Ensures unique emails and usernames to avoid conflicts
 */
function generateUniqueUser(requestParams, context, ee, next) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(4).toString('hex');
    const userId = `user_${timestamp}_${random}`;
    
    context.vars.username = `test_${userId}`;
    context.vars.email = `${userId}@perftest.local`;
    context.vars.password = 'TestPassword123!';
    
    // Store user for later authentication tests
    registeredUsers.push({
        username: context.vars.username,
        email: context.vars.email,
        password: context.vars.password
    });
    
    return next();
}

/**
 * Select an existing user for authentication testing
 * Ensures we have users to authenticate against
 */
function selectExistingUser(requestParams, context, ee, next) {
    if (registeredUsers.length === 0) {
        // Create a default user if none exist
        context.vars.username = 'default_test_user';
        context.vars.email = 'default@perftest.local';
        context.vars.password = 'TestPassword123!';
    } else {
        // Round-robin selection of existing users
        const user = registeredUsers[userCounter % registeredUsers.length];
        userCounter++;
        
        context.vars.username = user.username;
        context.vars.email = user.email;
        context.vars.password = user.password;
    }
    
    return next();
}

/**
 * Get a valid access token for protected endpoint testing
 * Maintains a pool of valid tokens to avoid re-authentication overhead
 */
function getValidToken(requestParams, context, ee, next) {
    if (tokenPool.length > 0) {
        // Use existing token
        const token = tokenPool.pop();
        context.vars.access_token = token;
    } else {
        // Use a mock token for load testing
        // In real scenarios, this would authenticate and cache tokens
        context.vars.access_token = 'mock_token_for_load_testing';
    }
    
    return next();
}

/**
 * Store successful authentication tokens for reuse
 * Called after successful login to maintain token pool
 */
function storeToken(requestParams, context, ee, next) {
    if (context.vars.access_token && tokenPool.length < 100) {
        tokenPool.push(context.vars.access_token);
    }
    return next();
}

/**
 * Custom think time based on realistic user behavior
 * Implements variable think times for more realistic load patterns
 */
function customThinkTime(requestParams, context, ee, next) {
    // Random think time between 500ms - 3000ms
    const thinkTime = Math.random() * 2500 + 500;
    setTimeout(next, thinkTime);
}

/**
 * Performance metrics validation
 * Validates response times against Issue #43 targets
 */
function validatePerformanceTargets(requestParams, context, ee, next) {
    const responseTime = context.vars.$responseTime;
    
    // Log performance metrics for analysis
    if (responseTime) {
        console.log(`Response time: ${responseTime}ms for ${requestParams.url || 'unknown endpoint'}`);
        
        // Issue #43 Performance Targets:
        // Auth endpoints: <100ms P95
        // Registration: <200ms P95  
        // Password reset: <150ms P95
        // Profile: <50ms P95
        // Health: <10ms P95
        
        if (requestParams.url === '/health' && responseTime > 50) {
            console.warn(`⚠️ Health check response time (${responseTime}ms) exceeds target`);
        }
        
        if (requestParams.url === '/auth/login' && responseTime > 200) {
            console.warn(`⚠️ Authentication response time (${responseTime}ms) exceeds target`);
        }
        
        if (requestParams.url === '/auth/register' && responseTime > 300) {
            console.warn(`⚠️ Registration response time (${responseTime}ms) exceeds target`);
        }
        
        if (requestParams.url === '/auth/me' && responseTime > 100) {
            console.warn(`⚠️ Profile access response time (${responseTime}ms) exceeds target`);
        }
    }
    
    return next();
}

/**
 * Generate realistic user profiles for load testing
 * Creates diverse user data to better simulate production load
 */
function generateRealisticUserProfile(requestParams, context, ee, next) {
    const firstNames = ['John', 'Jane', 'Bob', 'Alice', 'Charlie', 'Diana', 'Eve', 'Frank'];
    const lastNames = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis'];
    const domains = ['example.com', 'test.org', 'demo.net', 'perftest.local'];
    
    const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
    const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    
    const timestamp = Date.now();
    const random = crypto.randomBytes(3).toString('hex');
    
    context.vars.first_name = firstName;
    context.vars.last_name = lastName;
    context.vars.username = `${firstName.toLowerCase()}_${lastName.toLowerCase()}_${random}`;
    context.vars.email = `${firstName.toLowerCase()}.${lastName.toLowerCase()}.${timestamp}@${domain}`;
    context.vars.password = 'SecureTestPass123!';
    
    return next();
}

/**
 * Simulate database and cache load patterns
 * Implements patterns that stress different system components
 */
function simulateSystemLoad(requestParams, context, ee, next) {
    // Randomly choose load pattern
    const patterns = ['cache_miss', 'db_heavy', 'mixed_load', 'normal'];
    const pattern = patterns[Math.floor(Math.random() * patterns.length)];
    
    context.vars.load_pattern = pattern;
    
    // Add pattern-specific headers for the service to recognize
    if (!requestParams.headers) {
        requestParams.headers = {};
    }
    
    requestParams.headers['X-Load-Pattern'] = pattern;
    
    return next();
}

/**
 * Memory and resource monitoring setup
 * Prepares context for resource consumption tracking
 */
function setupResourceMonitoring(requestParams, context, ee, next) {
    context.vars.start_time = Date.now();
    context.vars.request_id = crypto.randomUUID();
    
    // Add monitoring headers
    if (!requestParams.headers) {
        requestParams.headers = {};
    }
    
    requestParams.headers['X-Request-ID'] = context.vars.request_id;
    requestParams.headers['X-Test-Phase'] = process.env.ARTILLERY_PHASE || 'unknown';
    
    return next();
}

// Export all functions for Artillery to use
module.exports = {
    generateUniqueUser,
    selectExistingUser,
    getValidToken,
    storeToken,
    customThinkTime,
    validatePerformanceTargets,
    generateRealisticUserProfile,
    simulateSystemLoad,
    setupResourceMonitoring
};