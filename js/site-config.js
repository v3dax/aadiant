// Public-safe site config for GitHub Pages
// Only include non-sensitive values here.
// Update BACKEND_BASE_URL to your public backend URL (e.g., Render service).

(function(){
  // Centralized config with environment-aware switching
  var LOCAL_HOSTNAMES = ['localhost', '127.0.0.1'];
  var isLocal = LOCAL_HOSTNAMES.indexOf(window.location.hostname) !== -1 || window.location.protocol === 'file:';

  // Local dev endpoints
  var LOCAL_BACKEND = 'http://127.0.0.1:8081';
  var LOCAL_DASHBOARD = 'http://localhost:8501';

  // Production endpoints (config, not code). Update only these constants for prod.
  var PROD_BACKEND = 'https://aadiant-backend.onrender.com';
  var PROD_DASHBOARD = 'https://aadiant-dashboard.onrender.com';

  // Resolve effective endpoints based on environment
  var backend = isLocal ? LOCAL_BACKEND : PROD_BACKEND;
  var dashboard = isLocal ? LOCAL_DASHBOARD : PROD_DASHBOARD;

  // Optional: allow runtime overrides via query params (?backend=...&dashboard=...)
  try {
    var qp = new URLSearchParams(window.location.search);
    backend = qp.get('backend') || backend;
    dashboard = qp.get('dashboard') || dashboard;
  } catch (e) {}

  window.BACKEND_BASE_URL = backend;
  window.DASHBOARD_URL = dashboard;
})();
