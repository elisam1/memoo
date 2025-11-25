const fs = require('fs');
const path = require('path');

const COMPANIES_FILE = path.join(__dirname, '../data/companies.json');

// Load all companies from JSON
const loadCompanies = () => {
  if (!fs.existsSync(COMPANIES_FILE)) return [];
  const raw = fs.readFileSync(COMPANIES_FILE, 'utf-8');
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
};

// Save companies to JSON safely
const saveCompanies = (companies) => {
  if (!Array.isArray(companies)) throw new Error('Invalid companies list');
  fs.writeFileSync(COMPANIES_FILE, JSON.stringify(companies, null, 2));
};

/**
 * Get the SMTP config for a given email
 * @param {string} email
 * @returns {object|null} { host, port, secure, auth: { user, pass } }
 */
const getCompanyByEmail = (email) => {
  if (!email) return null;
  const domain = email.split('@')[1].toLowerCase();
  const companies = loadCompanies();
  const company = companies.find(c => c.domain.toLowerCase() === domain);
  return company ? company.smtp : null;
};

module.exports = {
  loadCompanies,
  getCompanyByEmail,
  saveCompanies
};
