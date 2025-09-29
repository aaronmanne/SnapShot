import os
import json
import uuid
import subprocess
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import quote as url_quote
from flask import Flask, request, jsonify
from flask_cors import CORS

# Configure the logger
logging.basicConfig(
    level=logging.INFO,  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create a logger object (optional but recommended for modularity)
logger = logging.getLogger(__name__)  # Use the module name as the logger name

app = Flask(__name__)
CORS(app)

# Constants
TEMP_DIR = os.path.join(os.getcwd(), 'temp_sast')
RULES_DIR = os.path.join(os.getcwd(), 'semgrep-rules')
MAX_SAST_FINDINGS = 500
MAX_SCANNING_ITEMS = 20

# In-memory storage
sast_findings = []
sast_scanning = []
semgrep_initialized = False


def initialize_semgrep():
    """Initialize semgrep and clone rules repository"""
    global semgrep_initialized

    try:
        # Create temp directory if it doesn't exist
        if not os.path.exists(TEMP_DIR):
            os.makedirs(TEMP_DIR, exist_ok=True)

        # Check if semgrep is installed
        try:
            subprocess.run(['semgrep', '--version'], check=True, capture_output=True)
            logger.info('Semgrep is already installed')
            semgrep_initialized = True
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.info('Semgrep not found, FATAL!')

        logger.info(f'Semgrep initialization {"complete" if semgrep_initialized else "failed, using legacy analysis only"}')
    except Exception as e:
        logger.info(f'Error initializing semgrep: {str(e)}')
        logger.info('Continuing with legacy analysis only')
        semgrep_initialized = False


def run_semgrep_analysis(content, url, method, host, content_type, timestamp):
    """
    Run semgrep analysis on the content
    Returns an array of findings
    """
    global semgrep_initialized

    logger.info(f'Starting semgrep analysis for {url}')

    if not semgrep_initialized:
        logger.info('Semgrep not initialized, skipping analysis')
        return []

    try:
        findings = []
        file_id = str(uuid.uuid4())
        extension = '.txt'

        # Determine file extension based on content type
        if 'html' in content_type:
            extension = '.html'
        elif 'javascript' in content_type:
            extension = '.js'
        elif 'json' in content_type:
            extension = '.json'
        elif 'php' in content_type:
            extension = '.php'
        elif 'python' in content_type:
            extension = '.py'
        elif url.endswith('.js'):
            extension = '.js'
        elif url.endswith('.php'):
            extension = '.php'
        elif url.endswith('.py'):
            extension = '.py'

        temp_file_path = os.path.join(TEMP_DIR, f"{file_id}{extension}")
        logger.info(f'Processing file {url} with extension {extension}')

        # Write content to temp file
        with open(temp_file_path, 'w') as f:
            f.write(content)
        logger.info(f"File {url} written to temp file {temp_file_path}")
        # Determine which rule sets to use based on file type
        rulesets = []
        if extension in ['.js']:
            path = f"{RULES_DIR}/javascript"
            rulesets = [
                f"{path}/security",
            ]
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    rulesets.append(item_path)
        elif extension == '.html':
            path = f"{RULES_DIR}/html"
            rulesets = [
                f"{path}/security",
            ]
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    rulesets.append(item_path)
        elif extension == '.php':
            path = f"{RULES_DIR}/php"
            rulesets = [
                f"{path}/security",
            ]
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    rulesets.append(item_path)
        elif extension == '.py':
            path = f"{RULES_DIR}/python"
            rulesets = [
                f"{path}/security",
            ]
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    rulesets.append(item_path)

        # Only proceed if we have applicable rule sets
        if rulesets:
            logger.info(f"Applicable rule sets found for {url}: {rulesets}")
            # Run semgrep with appropriate rule sets
            for ruleset in rulesets:
                if os.path.exists(ruleset):
                    logger.info(f"Running semgrep with ruleset {ruleset} for {url}")
                    try:
                        command = ['semgrep', '--config', ruleset, temp_file_path, '--json']
                        result = subprocess.run(command, capture_output=True, text=True, check=True)
                        # Parse results
                        try:
                            semgrep_results = json.loads(result.stdout)
                            logger.info(f"Semgrep scan completed for {url} with {len(semgrep_results['results'])} findings") #TODO remove this later
                            if 'results' in semgrep_results and isinstance(semgrep_results['results'], list):
                                for finding in semgrep_results['results']:
                                    findings.append({
                                        'type': finding['check_id'].split('.')[-1].upper(),
                                        'cveId': f"[SEMGREP-{finding['check_id']}]",
                                        'severity': map_semgrep_severity_to_sast_severity(finding['extra']['severity']),
                                        'title': finding['extra']['message'],
                                        'url': url,
                                        'tech': extension[1:].upper(),
                                        'version': host or '',
                                        'indicator': finding['extra']['lines'],
                                        'method': method,
                                        'at': timestamp,
                                        'source': 'SEMGREP',
                                        'details': {
                                            'rule': finding['check_id'],
                                            'path': finding['path'],
                                            'startLine': finding['start']['line'],
                                            'endLine': finding['end']['line']
                                        }
                                    })
                        except json.JSONDecodeError:
                            logger.info('Error parsing semgrep results')
                    except subprocess.SubprocessError as e:
                        logger.info(f'Error running semgrep with ruleset {ruleset}: {str(e)}')
        else:
            logger.info(f"No applicable rule sets found for {url}")
        # Clean up temp file
        try:
            os.unlink(temp_file_path)
        except OSError:
            logger.info('Error removing temporary file')

        return findings
    except Exception as e:
        logger.info(f'Error in run_semgrep_analysis: {str(e)}')
        return []


def map_semgrep_severity_to_sast_severity(semgrep_severity):
    """Map semgrep severity to SAST severity"""
    severity_map = {
        'ERROR': 'CRITICAL',
        'WARNING': 'HIGH',
        'INFO': 'MEDIUM'
    }

    if semgrep_severity and semgrep_severity.upper() in severity_map:
        return severity_map[semgrep_severity.upper()]
    return 'MEDIUM'


def analyze_html(text, url, host, path, method, timestamp):
    """Analyze HTML content for potential vulnerabilities"""
    findings = []
    # Implementation of HTML analysis similar to SastService.js
    # Note: This would include checks for innerHTML, outerHTML, etc.
    return findings


def analyze_javascript(text, url, host, path, method, timestamp):
    """Analyze JavaScript content for potential vulnerabilities"""
    findings = []
    # Implementation of JavaScript analysis similar to SastService.js
    # Note: This would include checks for eval, Function constructor, etc.
    return findings


def analyze_generic(text, url, host, path, method, timestamp):
    """Analyze generic content for potential vulnerabilities"""
    findings = []
    # Implementation of generic analysis similar to SastService.js
    # Note: This would include checks for hardcoded credentials, SQL injections, etc.
    return findings


def get_file_type_from_content_type(headers):
    """Get file type from content type"""
    content_type = str(headers.get('content-type', '')).lower()

    if 'html' in content_type:
        return 'HTML'
    if 'javascript' in content_type:
        return 'JavaScript'
    if 'json' in content_type:
        return 'JSON'
    if 'xml' in content_type:
        return 'XML'
    if 'css' in content_type:
        return 'CSS'

    return 'Unknown'


def add_scanning_item(item):
    """Add an item to the scanning list"""
    global sast_scanning, MAX_SCANNING_ITEMS

    if not item or 'url' not in item:
        return sast_scanning

    # Remove existing item with the same URL if present
    sast_scanning = [scan for scan in sast_scanning if scan['url'] != item['url']]

    # Add new item
    sast_scanning.append(item)

    # Ensure we don't exceed the maximum
    if len(sast_scanning) > MAX_SCANNING_ITEMS:
        sast_scanning.pop(0)

    return sast_scanning


def update_scanning_item_status(url, status):
    """Update the status of a scanning item"""
    global sast_scanning

    for i, item in enumerate(sast_scanning):
        if item['url'] == url:
            sast_scanning[i]['status'] = status
            break

    return sast_scanning


def remove_scanning_item(url):
    """Remove an item from the scanning list"""
    global sast_scanning
    sast_scanning = [item for item in sast_scanning if item['url'] != url]
    return sast_scanning


def add_sast_findings(items):
    """Add findings to the collection"""
    global sast_findings, MAX_SAST_FINDINGS

    if not isinstance(items, list) or not items:
        return

    for item in items:
        sast_findings.append(item)
        if len(sast_findings) > MAX_SAST_FINDINGS:
            sast_findings.pop(0)


def analyze_sast(record, body, headers=None):
    """
    Performs static analysis on a response body
    Returns an array of findings
    """
    global sast_scanning, sast_findings

    if not record or not body:
        return []

    headers = headers or {}
    findings = []
    url = record.get('url', '')
    method = record.get('method', '')
    host = record.get('host', '')
    path = record.get('path', '')
    timestamp = record.get('timestamp', None)

    if not timestamp:
        from datetime import datetime
        timestamp = int(datetime.now().timestamp() * 1000)

    # Add to scanning list
    add_scanning_item({
        'url': url,
        'timestamp': timestamp,
        'status': 'analyzing',
        'type': get_file_type_from_content_type(headers) or 'unknown'
    })
    logger.info(f'Added {url} to scanning list')
    try:
        content_type = str(headers.get('content-type', '')).lower()
        is_html = 'html' in content_type
        is_js = ('javascript' in content_type or
                 'application/json' in content_type or
                 'application/x-javascript' in content_type or
                 url.endswith('.js'))
        is_text = ('text' in content_type or
                   is_html or
                   is_js or
                   'xml' in content_type)

        if not is_text or not body:
            # Remove from scanning list if not text content
            logger.info(f'Not a text content, removing from scanning list: {url}')
            remove_scanning_item(url)
            return []

        text = str(body or '')

        # First run semgrep analysis
        logger.info(f'Starting semgrep analysis for URL: {url}')
        semgrep_findings = run_semgrep_analysis(text, url, method, host, content_type, timestamp)
        findings.extend(semgrep_findings)

        # Also run our legacy analysis as a fallback
        # HTML analysis
        if is_html:
            findings.extend(analyze_html(text, url, host, path, method, timestamp))

        # JavaScript analysis
        if is_js or is_html:  # Also check for inline JS in HTML
            findings.extend(analyze_javascript(text, url, host, path, method, timestamp))

        # Generic analysis for all text files
        findings.extend(analyze_generic(text, url, host, path, method, timestamp))

        # Update scan status to completed
        update_scanning_item_status(url, 'completed')

        # Add findings to the collection
        if findings:
            add_sast_findings(findings)

        return findings
    except Exception as e:
        logger.info(f'Error in analyze_sast: {str(e)}')
        # Update scan status to error
        update_scanning_item_status(url, 'error')
        return []
    finally:
        # After a timeout, remove from scanning list
        import threading
        threading.Timer(2.0, lambda: remove_scanning_item(url)).start()


def clear_all():
    """Clear all findings and scanning items, also clean up temp directories"""
    global sast_findings, sast_scanning

    sast_findings = []
    sast_scanning = []

    # Clean up temp directory
    try:
        if os.path.exists(TEMP_DIR):
            # Remove all files in the temp directory
            for file in os.listdir(TEMP_DIR):
                try:
                    os.unlink(os.path.join(TEMP_DIR, file))
                except Exception as e:
                    logger.info(f'Error removing temporary file {file}: {str(e)}')
    except Exception as e:
        logger.info(f'Error cleaning up temporary directory: {str(e)}')


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'SAST Microservice',
        'initialized': semgrep_initialized
    })


@app.route('/api/sast/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        record = data.get('record')
        body = data.get('body')
        headers = data.get('headers', {})

        if not record or not body:
            return jsonify({'error': 'Missing record or body'}), 400

        findings = analyze_sast(record, body, headers)
        return jsonify({'findings': findings})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sast/findings', methods=['GET'])
def get_findings():
    try:
        return jsonify({'items': sast_findings})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sast/scanning', methods=['GET'])
def get_scanning():
    try:
        return jsonify({'items': sast_scanning})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sast/clear', methods=['POST'])
def clear():
    try:
        clear_all()
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    initialize_semgrep()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5002)), debug=False)