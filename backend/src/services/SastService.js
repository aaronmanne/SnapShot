import {v4 as uuidv4} from 'uuid';
import axios from 'axios';

// SastService - Static Application Security Testing service
// This service now acts as a proxy to the Python-based SAST microservice

class SastService {
    constructor() {
        this.sastFindings = [];
        this.sastScanning = [];
        this.MAX_SAST_FINDINGS = 500;
        this.MAX_SCANNING_ITEMS = 20;
        this.SAST_SERVICE_URL = process.env.SAST_SERVICE_URL || 'http://sast-service:5002';

        console.log(`SAST service URL: ${this.SAST_SERVICE_URL}`);

        // Check if the SAST service is running
        this.checkServiceStatus();
    }

    /**
     * Check if the SAST microservice is running
     */
    async checkServiceStatus() {
        try {
            const response = await axios.get(`${this.SAST_SERVICE_URL}/health`);
            if (response.status === 200) {
                console.log('SAST microservice is running');
                console.log(`SAST status: ${JSON.stringify(response.data)}`);

                // Sync findings and scanning status
                this.syncFromMicroservice();
            }
        } catch (error) {
            console.error('Error connecting to SAST microservice:', error.message);
        }
    }

    /**
     * Sync findings and scanning status from the microservice
     */
    async syncFromMicroservice() {
        try {
            const findingsResponse = await axios.get(`${this.SAST_SERVICE_URL}/api/sast/findings`);
            if (findingsResponse.status === 200 && findingsResponse.data.items) {
                this.sastFindings = findingsResponse.data.items;
            }

            const scanningResponse = await axios.get(`${this.SAST_SERVICE_URL}/api/sast/scanning`);
            if (scanningResponse.status === 200 && scanningResponse.data.items) {
                this.sastScanning = scanningResponse.data.items;
            }
        } catch (error) {
            console.error('Error syncing from SAST microservice:', error.message);
        }
    }

    /**
     * Performs static analysis on a response body
     * @param {Object} record - The request/response record
     * @param {String} body - The response body
     * @param {Object} headers - The response headers
     * @returns {Array} - Array of findings
     */
    async analyzeSast(record, body, headers = {}) {
        if (!record || !body) return [];

        // Add to scanning list temporarily until the microservice updates us
        this.addScanningItem({
            url: record?.url || '',
            timestamp: record?.timestamp || Date.now(),
            status: 'analyzing',
            type: this._getFileTypeFromContentType(headers) || 'unknown'
        });

        try {
            // Send the analysis request to the SAST microservice
            console.log('Sending analysis request to SAST microservice');
            const response = await axios.post(`${this.SAST_SERVICE_URL}/api/sast/analyze`, {
                record,
                body,
                headers
            });

            if (response.status === 200 && response.data.findings) {
                // Sync findings and scanning status after analysis
                await this.syncFromMicroservice();
                return response.data.findings;
            }

            return [];
        } catch (error) {
            console.error('Error in analyzeSast:', error.message);

            // Remove from scanning list on error
            setTimeout(() => {
                this.removeScanningItem(record?.url || '');
            }, 2000);

            return [];
        }
    }

    /**
     * Get file type from content type
     */
    _getFileTypeFromContentType(headers) {
        const contentType = String(headers['content-type'] || '').toLowerCase();

        if (contentType.includes('html')) return 'HTML';
        if (contentType.includes('javascript')) return 'JavaScript';
        if (contentType.includes('json')) return 'JSON';
        if (contentType.includes('xml')) return 'XML';
        if (contentType.includes('css')) return 'CSS';

        return 'Unknown';
    }

    /**
     * Add findings to the collection
     */
    addSastFindings(items = []) {
        if (!Array.isArray(items) || !items.length) return;
        for (const it of items) {
            this.sastFindings.push(it);
            if (this.sastFindings.length > this.MAX_SAST_FINDINGS) this.sastFindings.shift();
        }
    }

    /**
     * Get all static analysis findings
     */
    getSastFindings() {
        return this.sastFindings;
    }

    /**
     * Add an item to the scanning list
     */
    addScanningItem(item) {
        if (!item || !item.url) return;

        // Remove existing item with the same URL if present
        this.sastScanning = this.sastScanning.filter(scan => scan.url !== item.url);

        // Add new item
        this.sastScanning.push(item);

        // Ensure we don't exceed the maximum
        if (this.sastScanning.length > this.MAX_SCANNING_ITEMS) {
            this.sastScanning.shift();
        }

        return this.sastScanning;
    }

    /**
     * Update the status of a scanning item
     */
    updateScanningItemStatus(url, status) {
        const index = this.sastScanning.findIndex(item => item.url === url);
        if (index !== -1) {
            this.sastScanning[index].status = status;
        }
        return this.sastScanning;
    }

    /**
     * Remove an item from the scanning list
     */
    removeScanningItem(url) {
        this.sastScanning = this.sastScanning.filter(item => item.url !== url);
        return this.sastScanning;
    }

    /**
     * Get the current scanning items
     */
    getScanning() {
        return this.sastScanning;
    }

    /**
     * Clear all findings and scanning items
     */
    async clearAll() {
        try {
            // Clear findings in the microservice
            await axios.post(`${this.SAST_SERVICE_URL}/api/sast/clear`);

            // Clear local cache
            this.sastFindings = [];
            this.sastScanning = [];

            return true;
        } catch (error) {
            console.error('Error clearing SAST findings:', error.message);

            // Still clear local cache even if the microservice call fails
            this.sastFindings = [];
            this.sastScanning = [];

            return false;
        }
    }
}

// Create singleton instance
const sastService = new SastService();

// Export instance properties
const sastFindings = sastService.sastFindings;
const sastScanning = sastService.sastScanning;

// Export plain functions for easy import
const analyzeSast = (...args) => sastService.analyzeSast(...args);
const getSastFindings = (...args) => sastService.getSastFindings(...args);
const getScanning = (...args) => sastService.getScanning(...args);
const clearAll = (...args) => sastService.clearAll(...args);

export default sastService;
export {analyzeSast, getSastFindings, getScanning, clearAll, sastFindings, sastScanning};