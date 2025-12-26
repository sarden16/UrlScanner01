const STORAGE_KEY = 'urlscanner.history.v1';
const MAX_HISTORY_ITEMS = 10;

/**
 * Load scan history from localStorage
 * @returns {Array} Array of history items, or empty array if none found
 */
export function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error('Failed to load history:', error);
    return [];
  }
}

/**
 * Save scan history to localStorage
 * @param {Array} history - Array of history items to save
 * @returns {boolean} True if successful, false otherwise
 */
export function saveHistory(history) {
  try {
    if (!Array.isArray(history)) {
      console.error('History must be an array');
      return false;
    }
    
    // Keep only the most recent items
    const trimmed = history.slice(0, MAX_HISTORY_ITEMS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    return true;
  } catch (error) {
    console.error('Failed to save history:', error);
    return false;
  }
}

/**
 * Add a new item to history
 * @param {string} url - The URL that was scanned
 * @param {any} result - The scan result data
 * @returns {Array} Updated history array
 */
export function addToHistory(url, result) {
  const history = loadHistory();
  const newItem = {
    url,
    when: new Date().toISOString(),
    result
  };
  
  const updated = [newItem, ...history];
  saveHistory(updated);
  return updated;
}

/**
 * Clear all history
 * @returns {boolean} True if successful
 */
export function clearHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (error) {
    console.error('Failed to clear history:', error);
    return false;
  }
}

/**
 * Remove a specific history item by index
 * @param {number} index - Index of item to remove
 * @returns {Array} Updated history array
 */
export function removeHistoryItem(index) {
  const history = loadHistory();
  if (index >= 0 && index < history.length) {
    history.splice(index, 1);
    saveHistory(history);
  }
  return history;
}