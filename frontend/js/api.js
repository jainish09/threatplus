/**
 * Threat Intelligence Dashboard - API Service Layer
 *
 * Handles all backend API requests.
 *
 * Local development:
 *   http://localhost:8080
 *   http://localhost:8000
 *
 * Production:
 *   https://threatplus.onrender.com
 */

class ApiService {
  constructor() {
    // Detect whether the frontend is running locally
    const isLocalhost =
      window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1';

    // Backend URLs
    if (isLocalhost) {
      this.candidateUrls = [
        'http://127.0.0.1:8080',
        'http://localhost:8080',
        'http://127.0.0.1:8000',
        'http://localhost:8000'
      ];
    } else {
      // Production backend on Render
      this.candidateUrls = [
        'https://threatplus.onrender.com'
      ];
    }

    this.activeBaseUrl = null;
  }

  /**
   * Standard JSON HTTP request helper.
   *
   * Automatically uses:
   *   /api + endpoint
   *
   * Example:
   *   /reports
   * becomes:
   *   https://threatplus.onrender.com/api/reports
   */
  async request(endpoint, options = {}) {
    let lastError = null;

    const urlsToTry =
      this.activeBaseUrl !== null
        ? [
          this.activeBaseUrl,
          ...this.candidateUrls.filter(
            (url) => url !== this.activeBaseUrl
          )
        ]
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

          // Some endpoints may return an empty response
          const contentType = response.headers.get('content-type') || '';

          if (contentType.includes('application/json')) {
            return await response.json();
          }

          return await response.text();
        }

        // Try to read backend error
        let errorMsg = `Request failed with status ${response.status}`;

        try {
          const errData = await response.json();

          if (errData && (errData.detail || errData.message)) {
            errorMsg = errData.detail || errData.message;
          }
        } catch (e) {
          // Ignore JSON parsing errors
        }

        this.activeBaseUrl = base;

        throw new Error(errorMsg);
      } catch (err) {
        lastError = err;

        // If backend explicitly returned an error,
        // don't continue trying other URLs.
        if (
          err.message &&
          !err.message.includes('fetch') &&
          !err.message.includes('NetworkError') &&
          !err.message.includes('Failed to fetch')
        ) {
          throw err;
        }
      }
    }

    console.warn(
      `[API Warning] Could not reach backend at /api${endpoint}`
    );

    throw (
      lastError ||
      new Error(
        `Could not connect to backend server at /api${endpoint}.`
      )
    );
  }

  /**
   * GET /api/reports
   */
  async getReports({
    search = '',
    year = '',
    threatType = '',
    severity = '',
    page = 1,
    limit = 12,
    sortBy = 'createdAt',
    order = 'desc'
  } = {}) {
    const params = new URLSearchParams();

    if (search) {
      params.append('search', search);
    }

    if (year) {
      params.append('year', year);
    }

    if (threatType && threatType !== 'All') {
      params.append('threatType', threatType);
    }

    if (severity && severity !== 'All') {
      params.append('severity', severity);
    }

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
    return this.request(
      `/reports/${encodeURIComponent(reportId)}`
    );
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
  async getIocStream({
    search = '',
    feed = '',
    threatType = '',
    iocType = '',
    page = 1,
    limit = 20
  } = {}) {
    const params = new URLSearchParams();

    if (search) {
      params.append('search', search);
    }

    if (feed && feed !== 'All') {
      params.append('feed', feed);
    }

    if (threatType && threatType !== 'All') {
      params.append('threatType', threatType);
    }

    if (iocType && iocType !== 'All') {
      params.append('iocType', iocType);
    }

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
    return this.request(
      `/lab71/benchmark-redesign?iterations=${iterations}`,
      {
        method: 'POST'
      }
    );
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

// Make API service globally available
window.apiService = new ApiService();