/**
 * Threat Intelligence Dashboard - API Service Layer
 * Cleanly separates all data-fetching functions from the UI logic.
 * Automatically discovers active backend port (8080 or 8000) on 127.0.0.1 / localhost.
 */

class ApiService {
  constructor() {
    const isFastApiDirect = (window.location.protocol.startsWith('http') && (window.location.port === '8080' || window.location.port === '8000'));
    
    this.candidateUrls = isFastApiDirect 
      ? ['', 'http://127.0.0.1:8080', 'http://localhost:8080']
      : ['http://127.0.0.1:8080', 'http://localhost:8080', 'http://127.0.0.1:8000', 'http://localhost:8000', ''];
    
    this.activeBaseUrl = null;
  }

  /**
   * Helper method for standard JSON HTTP requests with port failover and error handling
   */
  async request(endpoint, options = {}) {
    let lastError = null;
    const urlsToTry = this.activeBaseUrl !== null 
      ? [this.activeBaseUrl, ...this.candidateUrls.filter(u => u !== this.activeBaseUrl)]
      : this.candidateUrls;

    for (const base of urlsToTry) {
      try {
        const url = `${base}/api${endpoint}`;
        const response = await fetch(url, {
          headers: {
            'Content-Type': 'application/json',
            ...(options.headers || {})
          },
          ...options
        });

        if (response.ok) {
          this.activeBaseUrl = base;
          return await response.json();
        } else {
          // Parse server JSON error if available
          let errorMsg = `Request failed with status ${response.status}`;
          try {
            const errData = await response.json();
            if (errData && (errData.detail || errData.message)) {
              errorMsg = errData.detail || errData.message;
            }
          } catch (e) {}
          this.activeBaseUrl = base;
          throw new Error(errorMsg);
        }
      } catch (err) {
        lastError = err;
        // If it's an explicit API error returned by backend (not connection failure), throw immediately
        if (err.message && !err.message.includes('fetch') && !err.message.includes('NetworkError') && !err.message.includes('Failed to fetch')) {
          throw err;
        }
      }
    }

    console.warn(`[API Warning] Could not reach backend at /api${endpoint}`);
    throw (lastError || new Error(`Could not connect to backend server at /api${endpoint}. Please ensure python main.py is running.`));
  }

  /**
   * GET /api/reports
   */
  async getReports({ search = '', year = '', threatType = '', severity = '', page = 1, limit = 12, sortBy = 'createdAt', order = 'desc' } = {}) {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (year) params.append('year', year);
    if (threatType && threatType !== 'All') params.append('threatType', threatType);
    if (severity && severity !== 'All') params.append('severity', severity);
    params.append('page', page);
    params.append('limit', limit);
    params.append('sort_by', sortBy);
    params.append('order', order);

    return this.request(`/reports?${params.toString()}`);
  }

  /**
   * GET /api/reports/:id
   */
  async getReportById(reportId) {
    return this.request(`/reports/${encodeURIComponent(reportId)}`);
  }

  /**
   * GET /api/reports/count
   */
  async getReportsCount() {
    return this.request('/reports/count');
  }

  /**
   * GET /api/ioc
   */
  async getIocStream({ search = '', feed = '', threatType = '', iocType = '', page = 1, limit = 20 } = {}) {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (feed && feed !== 'All') params.append('feed', feed);
    if (threatType && threatType !== 'All') params.append('threatType', threatType);
    if (iocType && iocType !== 'All') params.append('iocType', iocType);
    params.append('page', page);
    params.append('limit', limit);

    return this.request(`/ioc?${params.toString()}`);
  }

  /**
   * GET /api/cache
   */
  async getCacheStats() {
    return this.request('/cache');
  }

  /**
   * GET /api/working-set
   */
  async getWorkingSetAnalysis() {
    return this.request('/working-set');
  }
  async getWorkingSet() {
    return this.getWorkingSetAnalysis();
  }

  /**
   * GET /api/random-read/status
   */
  async getRandomReadStatus() {
    return this.request('/random-read/status');
  }

  /**
   * POST /api/random-read/start
   */
  async startRandomReadExperiment(reads = 500) {
    return this.request(`/random-read/start?reads=${reads}`, {
      method: 'POST'
    });
  }
  async startRandomRead(reads = 500) {
    return this.startRandomReadExperiment(reads);
  }

  /**
   * POST /api/random-read/stop
   */
  async stopRandomReadExperiment() {
    return this.request('/random-read/stop', {
      method: 'POST'
    });
  }

  /**
   * GET /api/lab71/schema-analysis
   */
  async getLab71SchemaAnalysis() {
    return this.request('/lab71/schema-analysis');
  }
  async getLab71Analysis() {
    return this.getLab71SchemaAnalysis();
  }

  /**
   * POST /api/lab71/benchmark-redesign
   */
  async benchmarkLab71Redesign(iterations = 100) {
    return this.request(`/lab71/benchmark-redesign?iterations=${iterations}`, {
      method: 'POST'
    });
  }
  async runRedesignBenchmark(iterations = 100) {
    return this.benchmarkLab71Redesign(iterations);
  }

  /**
   * GET /api/sync/stats
   */
  async getLiveSyncStats() {
    return this.request('/sync/stats');
  }

  /**
   * POST /api/sync/malwarebazaar
   */
  async syncMalwareBazaar(limit = 50) {
    return this.request(`/sync/malwarebazaar?limit=${limit}`, {
      method: 'POST'
    });
  }

  /**
   * POST /api/sync/virustotal
   */
  async syncVirusTotal() {
    return this.request('/sync/virustotal', {
      method: 'POST'
    });
  }

  /**
   * POST /api/sync/all-live
   */
  async syncAllLiveFeeds(limit = 50) {
    return this.request(`/sync/all-live?limit=${limit}`, {
      method: 'POST'
    });
  }

  /**
   * GET /api/taxonomy
   */
  async getTaxonomy() {
    return this.request('/taxonomy');
  }

  /**
   * POST /api/sync/vt-lookup
   */
  async lookupVirusTotal(target, targetType = 'auto') {
    return this.request('/sync/vt-lookup', {
      method: 'POST',
      body: JSON.stringify({
        target: target,
        target_type: targetType
      })
    });
  }

  /**
   * GET /api/sync/vt-scans
   */
  async getRecentVtScans() {
    return this.request('/sync/vt-scans');
  }

  /**
   * POST /api/ioc/verify
   */
  async verifyTarget(target) {
    return this.request('/ioc/verify', {
      method: 'POST',
      body: JSON.stringify({
        target: target
      })
    });
  }
}

window.apiService = new ApiService();




