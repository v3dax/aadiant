// Public-safe site config for GitHub Pages
// Only include non-sensitive values here.
// Update BACKEND_BASE_URL to your public backend URL (e.g., Render service).

(function(){
  // Backend API URL
  var DEFAULT_BACKEND_LOCAL = 'http://127.0.0.1:8081';
  var PUBLIC_BACKEND = 'https://aadiant-backend.onrender.com';

  // Dashboard (Streamlit) URL
  var DEFAULT_DASHBOARD_LOCAL = 'http://localhost:8501';
  var PUBLIC_DASHBOARD = DEFAULT_DASHBOARD_LOCAL; // Update after Streamlit is deployed (e.g., 'https://aadiant-dashboard.onrender.com')

  window.BACKEND_BASE_URL = PUBLIC_BACKEND || DEFAULT_BACKEND_LOCAL;
  window.DASHBOARD_URL = PUBLIC_DASHBOARD || DEFAULT_DASHBOARD_LOCAL;
})();
