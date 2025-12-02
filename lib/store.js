const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');
const { getFirestore } = require('./firebaseAdmin');

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

const useFirestore = () => String(process.env.FIRESTORE_ENABLED || 'true').toLowerCase() === 'true';

const listUsersAsync = async () => {
  if (!useFirestore()) return getUsers();
  const db = getFirestore();
  if (!db) return getUsers();
  const snap = await db.collection('users').get();
  return snap.docs.map(d => d.data());
};

const saveUserAsync = async (user) => {
  if (!useFirestore()) {
    const users = getUsers();
    const idx = users.findIndex(u => u.email === user.email);
    if (idx >= 0) users[idx] = user; else users.push(user);
    saveUsers(users);
    return;
  }
  const db = getFirestore();
  if (!db) return;
  await db.collection('users').doc(user.email).set(user, { merge: true });
};

const deleteUserAsync = async (email) => {
  if (!useFirestore()) {
    let users = getUsers();
    users = users.filter(u => u.email !== email);
    saveUsers(users);
    return;
  }
  const db = getFirestore();
  if (!db) return;
  await db.collection('users').doc(email).delete();
};

const listMemosByHrAsync = async (email) => {
  if (!useFirestore()) {
    const dbLocal = get();
    return dbLocal.memos.filter(m => m.hrEmail === email);
  }
  const db = getFirestore();
  if (!db) return get().memos.filter(m => m.hrEmail === email);
  const snap = await db.collection('memos').where('hrEmail', '==', email).get();
  return snap.docs.map(d => d.data());
};

const listMemosByManagerAsync = async (email) => {
  if (!useFirestore()) {
    const dbLocal = get();
    return dbLocal.memos.filter(m => m.managerEmail === email);
  }
  const db = getFirestore();
  if (!db) return get().memos.filter(m => m.managerEmail === email);
  const snap = await db.collection('memos').where('managerEmail', '==', email).get();
  return snap.docs.map(d => d.data());
};

const addMemoAsync = async (memo) => {
  if (!useFirestore()) {
    const dbLocal = get();
    dbLocal.memos.push(memo);
    save(dbLocal);
    return;
  }
  const db = getFirestore();
  if (!db) return;
  await db.collection('memos').doc(memo.id).set(memo);
};

const getMemoByIdAsync = async (id) => {
  if (!useFirestore()) {
    const dbLocal = get();
    return dbLocal.memos.find(m => m.id === id) || null;
  }
  const db = getFirestore();
  if (!db) {
    const dbLocal = get();
    return dbLocal.memos.find(m => m.id === id) || null;
  }
  const doc = await db.collection('memos').doc(id).get();
  return doc.exists ? doc.data() : null;
};

const updateMemoStatusAsync = async (id, status) => {
  if (!useFirestore()) {
    const dbLocal = get();
    const memo = dbLocal.memos.find(m => m.id === id);
    if (memo) { memo.status = status; save(dbLocal); }
    return;
  }
  const db = getFirestore();
  if (!db) return;
  await db.collection('memos').doc(id).set({ status }, { merge: true });
};

const addReplyAsync = async (id, reply) => {
  if (!useFirestore()) {
    const dbLocal = get();
    const memo = dbLocal.memos.find(m => m.id === id);
    if (memo) { memo.replies.push(reply); save(dbLocal); }
    return;
  }
  const db = getFirestore();
  if (!db) return;
  const ref = db.collection('memos').doc(id);
  const doc = await ref.get();
  if (!doc.exists) return;
  const data = doc.data();
  const replies = Array.isArray(data.replies) ? data.replies.slice() : [];
  replies.push(reply);
  await ref.set({ replies }, { merge: true });
};

const purgeAllAsync = async () => {
  if (!useFirestore()) {
    save({ memos: [] });
    saveUsers([]);
    return;
  }
  const db = getFirestore();
  if (!db) return;
  const memos = await db.collection('memos').get();
  const users = await db.collection('users').get();
  const batch = db.batch();
  memos.docs.forEach(d => batch.delete(d.ref));
  users.docs.forEach(d => batch.delete(d.ref));
  await batch.commit();
};

module.exports = {
  get,
  save,
  getUsers,
  saveUsers,
  listUsersAsync,
  saveUserAsync,
  deleteUserAsync,
  listMemosByHrAsync,
  listMemosByManagerAsync,
  addMemoAsync,
  getMemoByIdAsync,
  updateMemoStatusAsync,
  addReplyAsync,
  purgeAllAsync,
};
