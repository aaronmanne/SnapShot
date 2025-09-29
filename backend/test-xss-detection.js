// Test script to verify enhanced XSS detection capabilities
import sastService, { analyzeSast, clearAll } from './src/services/SastService.js';

// Wait for initialization
setTimeout(runTests, 2000);

function runTests() {
  console.log('Running XSS detection tests...');
  
  // Test HTML with Google XSS Game Level 1 style vulnerability
  testHtml();
  
  // Test JavaScript with DOM-based XSS vulnerabilities
  testJavaScript();
  
  // Test combined HTML and JavaScript
  testCombined();
}

function testHtml() {
  console.log('\n=== Testing HTML XSS Detection ===');
  
  // Google XSS Game Level 1 style vulnerability
  const googleXssGameLevel1 = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>XSS Game</title>
    </head>
    <body>
      <h1>Level 1: Hello, world of XSS</h1>
      <div>
        Your input:
        <div id="user-input">CONTENT_FROM_USER</div>
      </div>
      
      <script>
        // Get the user input from the URL
        const input = new URLSearchParams(window.location.search).get('input');
        
        // Directly insert the user input into the page (vulnerable!)
        document.getElementById('user-input').innerHTML = input;
      </script>
    </body>
    </html>
  `;
  
  const findings = sastService.analyzeSast(
    {
      url: 'https://example.com/level1?input=<script>alert(1)</script>',
      method: 'GET',
      host: 'example.com',
      path: '/level1',
      timestamp: Date.now()
    },
    googleXssGameLevel1,
    { 'content-type': 'text/html' }
  );
  
  console.log(`Found ${findings.length} HTML vulnerabilities:`);
  findings.forEach(finding => {
    console.log(` - [${finding.severity}] ${finding.title}`);
  });
}

function testJavaScript() {
  console.log('\n=== Testing JavaScript XSS Detection ===');
  
  // DOM-based XSS similar to alert1 challenge
  const domBasedXssCode = `
    // Get URL parameters
    const params = new URLSearchParams(window.location.search);
    const name = params.get('name');
    
    // Vulnerable code for rendering user input
    document.getElementById('greeting').innerHTML = 'Hello, ' + name;
    
    // Common DOM XSS pattern
    const hash = window.location.hash.substring(1);
    const element = document.createElement('div');
    element.innerHTML = decodeURIComponent(hash);
    document.body.appendChild(element);
    
    // Eval-based vulnerabilities
    function runUserCode(code) {
      eval(code);
    }
    
    // Function constructor vulnerability
    const dynamicFunc = new Function(params.get('callback'));
    dynamicFunc();
    
    // Alert detection
    const alertMessage = params.get('message');
    if (alertMessage) {
      alert(alertMessage);
    }
  `;
  
  const findings = sastService.analyzeSast(
    {
      url: 'https://example.com/page?name=<img src=x onerror=alert(1)>',
      method: 'GET',
      host: 'example.com',
      path: '/page',
      timestamp: Date.now()
    },
    domBasedXssCode,
    { 'content-type': 'application/javascript' }
  );
  
  console.log(`Found ${findings.length} JavaScript vulnerabilities:`);
  findings.forEach(finding => {
    console.log(` - [${finding.severity}] ${finding.title}`);
  });
}

function testCombined() {
  console.log('\n=== Testing Combined HTML+JS XSS Detection ===');
  
  const combinedCode = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Vulnerable Page</title>
    </head>
    <body>
      <div id="content"></div>
      
      <script>
        // Multiple vulnerabilities in one page
        
        // 1. Reflected XSS
        const name = new URLSearchParams(window.location.search).get('name');
        document.getElementById('content').innerHTML = 'Welcome, ' + name;
        
        // 2. DOM-based XSS with hash
        window.addEventListener('hashchange', function() {
          const data = location.hash.substring(1);
          document.querySelector('.result').innerHTML = decodeURIComponent(data);
        });
        
        // 3. DOM-based XSS with document.write
        const theme = new URLSearchParams(window.location.search).get('theme');
        document.write('<div class="theme-' + theme + '">Themed content</div>');
        
        // 4. Eval-based vulnerability
        const calculate = new URLSearchParams(window.location.search).get('calc');
        if (calculate) {
          const result = eval(calculate);
          document.getElementById('result').innerText = result;
        }
      </script>
    </body>
    </html>
  `;
  
  const findings = sastService.analyzeSast(
    {
      url: 'https://example.com/vulnerable?name=<script>alert(1)</script>&theme=blue&calc=alert(document.domain)',
      method: 'GET',
      host: 'example.com',
      path: '/vulnerable',
      timestamp: Date.now()
    },
    combinedCode,
    { 'content-type': 'text/html' }
  );
  
  console.log(`Found ${findings.length} combined vulnerabilities:`);
  findings.forEach(finding => {
    console.log(` - [${finding.severity}] ${finding.title}`);
  });
  
  // Group findings by type
  const byType = findings.reduce((acc, finding) => {
    if (!acc[finding.type]) acc[finding.type] = [];
    acc[finding.type].push(finding);
    return acc;
  }, {});
  
  console.log('\n=== Findings by Type ===');
  Object.keys(byType).forEach(type => {
    console.log(`\n${type}: ${byType[type].length} findings`);
    byType[type].forEach(finding => {
      console.log(` - [${finding.severity}] ${finding.title}`);
    });
  });
}