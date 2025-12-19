// Public-safe site config for GitHub Pages
// Only include non-sensitive values here.
// Update BACKEND_BASE_URL to your public backend URL (e.g., Render service).

(function(){
  // Default to local dev if not set
  var DEFAULT_LOCAL = 'http://127.0.0.1:8081';
  // Replace this with your Render URL after deploy
  var PUBLIC_BACKEND = DEFAULT_LOCAL; // e.g., 'https://aadiant-backend.onrender.com'

  window.BACKEND_BASE_URL = PUBLIC_BACKEND || DEFAULT_LOCAL;
})();
