// lib/store.js
const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, '../data/db.json');
const USERS_FILE = path.join(__dirname, '../data/users.json');

const ensureFile = (file, defaultData = '{}') => {
  if (!fs.existsSync(file)) fs.writeFileSync(file, defaultData);
};
ensureFile(DB_FILE, JSON.stringify({ memos: [] }, null, 2));
ensureFile(USERS_FILE, JSON.stringify([], null, 2));

const get = () => {
  const raw = fs.readFileSync(DB_FILE, 'utf-8');
  return JSON.parse(raw);
};

const save = (data) => {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
};

const getUsers = () => {
  const raw = fs.readFileSync(USERS_FILE, 'utf-8');
  return JSON.parse(raw);
};

const saveUsers = (users) => {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

module.exports = { get, save, getUsers, saveUsers };
