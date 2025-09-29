// Test script for running SAST against realistic XSS examples
import fs from 'fs';
import path from 'path';
import sastService, { analyzeSast, clearAll } from './src/services/SastService.js';

// Wait for initialization
setTimeout(runTests, 2000);

function runTests() {
  console.log('Running SAST analysis on realistic XSS examples...');
  
  // Test Google XSS Game Level 1 simulation
  testGoogleXssGameLevel1();
  
  // You could add more test cases here
}

function testGoogleXssGameLevel1() {
  console.log('\n=== Testing Google XSS Game Level 1 Simulation ===');
  
  // Read the HTML file
  try {
    const html = fs.readFileSync(path.join(process.cwd(), 'test-xss-level1.html'), 'utf8');
    
    // Create a mock record
    const mockRecord = {
      url: 'https://example.com/xss-game/level1?query=<script>alert(1)</script>',
      method: 'GET',
      host: 'example.com',
      path: '/xss-game/level1',
      timestamp: Date.now()
    };
    
    // Run SAST analysis
    const findings = analyzeSast(mockRecord, html, { 'content-type': 'text/html' });
    
    console.log(`Found ${findings.length} vulnerabilities in Google XSS Game Level 1 simulation:`);
    findings.forEach(finding => {
      console.log(` - [${finding.severity}] ${finding.title}`);
    });
    
    // Check for specific vulnerability types
    const xssFindings = findings.filter(finding => finding.type === 'XSS' || finding.type === 'DOM-XSS');
    console.log(`\nFound ${xssFindings.length} XSS-related vulnerabilities:`);
    xssFindings.forEach(finding => {
      console.log(` - [${finding.severity}] ${finding.title}`);
      console.log(`   Indicator: ${finding.indicator.substring(0, 100)}...`);
    });
    
    // Evaluate if the detection is successful
    const criticalXssFindings = findings.filter(finding => 
      (finding.type === 'XSS' || finding.type === 'DOM-XSS') && 
      (finding.severity === 'HIGH' || finding.severity === 'CRITICAL')
    );
    
    if (criticalXssFindings.length > 0) {
      console.log('\n✅ SUCCESS: Detected critical XSS vulnerabilities in Google XSS Game Level 1 simulation');
    } else {
      console.log('\n❌ FAILURE: Did not detect any critical XSS vulnerabilities');
    }
  } catch (error) {
    console.error('Error reading test file:', error.message);
  }
}