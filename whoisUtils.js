/**
 * Utility functions for parsing and displaying WHOIS information
 */

/**
 * Check if WHOIS data exists and has meaningful content
 * @param {object} whois - WHOIS data object
 * @returns {boolean} True if WHOIS data is available
 */
export function hasWhoisData(whois) {
  if (!whois || typeof whois !== 'object') return false;
  
  // Check if at least one meaningful field exists
  return !!(
    whois.domain_name || whois.domain ||
    whois.registrar ||
    whois.org || whois.organization ||
    whois.country ||
    whois.creation_date || whois.created || whois.creationDate ||
    whois.expiration_date || whois.expires || whois.expirationDate ||
    whois.name_servers || whois.nameServers
  );
}

/**
 * Normalize field names from various WHOIS formats
 * @param {object} whois - Raw WHOIS data
 * @returns {object} Normalized field names
 */
function normalizeWhoisFields(whois) {
  if (!whois) return {};
  
  return {
    domain_name: whois.domain_name || whois.domain || whois.domainName,
    registrar: whois.registrar || whois.sponsoring_registrar,
    org: whois.org || whois.organization || whois.registrant_organization || whois.registrant_org,
    country: whois.country || whois.registrant_country,
    state: whois.state || whois.registrant_state,
    city: whois.city || whois.registrant_city,
    creation_date: whois.creation_date || whois.created || whois.creationDate || whois.created_date,
    updated_date: whois.updated_date || whois.updated || whois.updatedDate || whois.last_updated,
    expiration_date: whois.expiration_date || whois.expires || whois.expirationDate || whois.expiry_date,
    name_servers: whois.name_servers || whois.nameServers || whois.nserver,
    status: whois.status || whois.domain_status || whois.domainStatus,
    registrant_name: whois.registrant_name || whois.registrant,
    registrant_email: whois.registrant_email || whois.email,
    dnssec: whois.dnssec
  };
}

/**
 * Format a date from WHOIS data
 * @param {string|array} dateValue - Date value (can be array or string)
 * @returns {string|null} Formatted date string or null
 */
export function formatWhoisDate(dateValue) {
  if (!dateValue) return null;
  
  try {
    // WHOIS dates are often returned as arrays
    const dateStr = Array.isArray(dateValue) ? dateValue[0] : dateValue;
    if (!dateStr) return null;
    
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return dateStr; // Return as-is if invalid
    
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch {
    return null;
  }
}

/**
 * Calculate domain age in years from creation date
 * @param {string|array} creationDate - Domain creation date
 * @returns {number|null} Age in years (rounded to 1 decimal) or null
 */
export function calculateDomainAge(creationDate) {
  if (!creationDate) return null;
  
  try {
    const dateStr = Array.isArray(creationDate) ? creationDate[0] : creationDate;
    if (!dateStr) return null;
    
    const created = new Date(dateStr);
    if (isNaN(created.getTime())) return null;
    
    const now = new Date();
    const ageMs = now - created;
    const ageYears = ageMs / (1000 * 60 * 60 * 24 * 365.25);
    
    return Math.round(ageYears * 10) / 10; // Round to 1 decimal place
  } catch {
    return null;
  }
}

/**
 * Calculate domain age in days from creation date
 * @param {string|array} creationDate - Domain creation date
 * @returns {number|null} Age in days or null
 */
export function calculateDomainAgeInDays(creationDate) {
  if (!creationDate) return null;
  
  try {
    const dateStr = Array.isArray(creationDate) ? creationDate[0] : creationDate;
    if (!dateStr) return null;
    
    const created = new Date(dateStr);
    if (isNaN(created.getTime())) return null;
    
    const now = new Date();
    const ageMs = now - created;
    const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
    
    return ageDays;
  } catch {
    return null;
  }
}

/**
 * Calculate days until domain expiration
 * @param {string|array} expirationDate - Domain expiration date
 * @returns {number|null} Days until expiration or null
 */
export function daysUntilExpiration(expirationDate) {
  if (!expirationDate) return null;
  
  try {
    const dateStr = Array.isArray(expirationDate) ? expirationDate[0] : expirationDate;
    if (!dateStr) return null;
    
    const expires = new Date(dateStr);
    if (isNaN(expires.getTime())) return null;
    
    const now = new Date();
    const diffMs = expires - now;
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    return diffDays;
  } catch {
    return null;
  }
}

/**
 * Check if domain is expired
 * @param {string|array} expirationDate - Domain expiration date
 * @returns {boolean} True if domain is expired
 */
export function isDomainExpired(expirationDate) {
  const days = daysUntilExpiration(expirationDate);
  return days !== null && days < 0;
}

/**
 * Check if domain is expiring soon (within 30 days)
 * @param {string|array} expirationDate - Domain expiration date
 * @returns {boolean} True if domain expires in 30 days or less
 */
export function isDomainExpiringSoon(expirationDate) {
  const days = daysUntilExpiration(expirationDate);
  return days !== null && days >= 0 && days <= 30;
}

/**
 * Format name servers list
 * @param {array|string} nameServers - Name servers data
 * @returns {array} Array of name server strings
 */
export function formatNameServers(nameServers) {
  if (!nameServers) return [];
  
  if (Array.isArray(nameServers)) {
    return nameServers.filter(ns => ns && typeof ns === 'string');
  }
  
  if (typeof nameServers === 'string') {
    return [nameServers];
  }
  
  return [];
}

/**
 * Extract registrant information from WHOIS data
 * @param {object} whois - WHOIS data object (normalized)
 * @returns {object} Registrant information
 */
export function getRegistrantInfo(whois) {
  if (!whois) return null;
  
  return {
    name: whois.registrant_name || whois.registrant || null,
    organization: whois.org || whois.registrant_organization || null,
    email: whois.registrant_email || whois.email || null,
    country: whois.country || whois.registrant_country || null,
    state: whois.state || whois.registrant_state || null,
    city: whois.city || whois.registrant_city || null
  };
}

/**
 * Get domain status information
 * @param {object} whois - WHOIS data object (normalized)
 * @returns {array} Array of status strings
 */
export function getDomainStatus(whois) {
  if (!whois) return [];
  
  const status = whois.status || whois.domain_status;
  
  if (Array.isArray(status)) {
    return status.filter(s => s && typeof s === 'string');
  }
  
  if (typeof status === 'string') {
    return [status];
  }
  
  return [];
}

/**
 * Parse WHOIS data into a structured format
 * @param {object} whois - Raw WHOIS data
 * @returns {object} Structured WHOIS information
 */
export function parseWhoisData(whois) {
  if (!hasWhoisData(whois)) return null;
  
  // Normalize field names first
  const normalized = normalizeWhoisFields(whois);
  
  const domainAge = calculateDomainAge(normalized.creation_date);
  const domainAgeInDays = calculateDomainAgeInDays(normalized.creation_date);
  const daysToExpiry = daysUntilExpiration(normalized.expiration_date);
  
  return {
    domain: normalized.domain_name || null,
    registrar: normalized.registrar || null,
    registrant: getRegistrantInfo(normalized),
    dates: {
      created: formatWhoisDate(normalized.creation_date),
      updated: formatWhoisDate(normalized.updated_date),
      expires: formatWhoisDate(normalized.expiration_date),
      age: domainAge,
      ageInDays: domainAgeInDays,
      daysToExpiry: daysToExpiry
    },
    nameServers: formatNameServers(normalized.name_servers),
    status: getDomainStatus(normalized),
    dnssec: normalized.dnssec || null,
    isExpired: isDomainExpired(normalized.expiration_date),
    isExpiringSoon: isDomainExpiringSoon(normalized.expiration_date),
    raw: whois
  };
}

/**
 * Get a risk indicator based on domain age
 * @param {number} ageYears - Domain age in years
 * @returns {object} Risk level and color
 */
export function getDomainAgeRisk(ageYears) {
  if (ageYears === null || ageYears === undefined) {
    return { level: 'unknown', color: '#6b7280', label: 'Unknown' };
  }
  
  if (ageYears < 0.5) {
    return { level: 'high', color: '#ef4444', label: 'Very New (High Risk)' };
  } else if (ageYears < 1) {
    return { level: 'medium', color: '#f59e0b', label: 'New (Medium Risk)' };
  } else if (ageYears < 3) {
    return { level: 'low', color: '#10b981', label: 'Established' };
  } else {
    return { level: 'minimal', color: '#059669', label: 'Well Established' };
  }
}

/**
 * Check if registrar is known and reputable
 * @param {string} registrar - Registrar name
 * @returns {boolean} True if registrar is well-known
 */
export function isKnownRegistrar(registrar) {
  if (!registrar || typeof registrar !== 'string') return false;

  const knownRegistrars = [
    'godaddy',
    'namecheap',
    'cloudflare',
    'google',
    'tucows',
    'enom',
    'network solutions',
    'register.com',
    'gandi',
    'hover',
    'name.com',
    'dynadot',
    'porkbun',
    'squarespace'
  ];

  const lowerRegistrar = registrar.toLowerCase();
  return knownRegistrars.some(known => lowerRegistrar.includes(known));
}

/**
 * Debug helper - Log all available WHOIS fields
 * Useful for seeing what data is actually available
 * @param {object} whois - WHOIS data object
 */
export function debugWhoisFields(whois) {
  if (!whois) {
    console.log('❌ No WHOIS data available');
    return;
  }

  console.log('🔍 Available WHOIS fields:');
  console.log(JSON.stringify(whois, null, 2));

  console.log('\n📋 Field Summary:');
  Object.keys(whois).forEach(key => {
    const value = whois[key];
    const type = Array.isArray(value) ? 'array' : typeof value;
    console.log(`  ${key}: ${type} - ${value !== null && value !== undefined ? '✓' : '✗'}`);
  });
}
