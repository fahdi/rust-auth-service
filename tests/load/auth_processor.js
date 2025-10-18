module.exports = {
  generateRandomEmail,
  generateRandomPassword,
  setUserContext,
  validateAuthResponse,
  measurePerformance
};

function generateRandomEmail(context, events, done) {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 10000);
  context.vars.randomEmail = `test-${timestamp}-${random}@example.com`;
  return done();
}

function generateRandomPassword(context, events, done) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < 12; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  context.vars.randomPassword = password;
  return done();
}

function setUserContext(requestParams, context, ee, next) {
  // Add unique identifiers for load testing
  context.vars.userAgent = 'Artillery-Load-Test';
  context.vars.testId = `load-test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  // Add request headers for tracking
  if (!requestParams.headers) {
    requestParams.headers = {};
  }
  requestParams.headers['X-Test-ID'] = context.vars.testId;
  requestParams.headers['X-Load-Test'] = 'true';
  
  return next();
}

function validateAuthResponse(requestParams, response, context, ee, next) {
  if (response.statusCode !== 200 && response.statusCode !== 201) {
    console.log(`Authentication failed with status: ${response.statusCode}`);
    console.log(`Response body: ${response.body}`);
    
    // Emit custom metric for failed authentication
    ee.emit('customStat', 'auth.failures', 1);
  } else {
    // Emit custom metric for successful authentication
    ee.emit('customStat', 'auth.successes', 1);
    
    // Validate JWT token format if present
    try {
      const responseBody = JSON.parse(response.body);
      if (responseBody.access_token) {
        const tokenParts = responseBody.access_token.split('.');
        if (tokenParts.length !== 3) {
          console.log('Invalid JWT token format received');
          ee.emit('customStat', 'auth.invalid_token', 1);
        } else {
          ee.emit('customStat', 'auth.valid_token', 1);
        }
      }
    } catch (e) {
      console.log('Failed to parse authentication response:', e.message);
      ee.emit('customStat', 'auth.parse_errors', 1);
    }
  }
  
  return next();
}

function measurePerformance(requestParams, response, context, ee, next) {
  const responseTime = response.timings ? response.timings.response : 0;
  
  // Emit custom metrics based on response time thresholds
  if (responseTime > 1000) {
    ee.emit('customStat', 'performance.slow_responses', 1);
  } else if (responseTime > 500) {
    ee.emit('customStat', 'performance.medium_responses', 1);
  } else {
    ee.emit('customStat', 'performance.fast_responses', 1);
  }
  
  // Track endpoint-specific performance
  const endpoint = requestParams.url || 'unknown';
  ee.emit('customStat', `performance.${endpoint.replace(/[^a-zA-Z0-9]/g, '_')}`, responseTime);
  
  return next();
}