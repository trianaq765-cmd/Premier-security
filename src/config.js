// ============================================================
// ⚙️ CONFIGURATION
// ============================================================

module.exports = {
    PORT: process.env.PORT || 3000,
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-to-secure-key',
    
    RATE_LIMIT: {
        WINDOW_MS: 60 * 1000,
        MAX_REQUESTS: 60
    }
};
