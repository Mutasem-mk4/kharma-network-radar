// KHARMA SENTINEL - Global State & Constants
const SESSION_TOKEN = document.querySelector('meta[name="session-token"]')?.content || localStorage.getItem('kharma_jwt') || "";

var allConnections = [];
var knownThreats = new Set();
var lastPacketsJson = "";
var isPro = false;
var globe; // Map instance
var bwChart; // Chart instance

var myLat = 31.9522;
var myLon = 35.2332;

const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    info: '#6366f1'
};

const eventIcons = {
    THREAT: '🚨',
    BLOCKED: '🛡️',
    COMMUNITY_FLAG: '👥',
    DPI_ALERT: '⚠️'
};

// State for row rendering
const _rowCache = new Map();
var currentLang = 'EN';
