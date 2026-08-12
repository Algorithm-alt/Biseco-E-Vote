const db = require('./db');

const SAFE_TABLES = [
  'users',
  'elections',
  'positions',
  'candidates',
  'votes',
  'audit_logs',
  'announcements',
  'voter_election_access',
];

const SAFE_COLUMNS = {
  users: [
    'id',
    'code',
    'password',
    'role',
    'has_voted',
    'totp_secret',
    'totp_enabled',
    'pin',
    'email',
    'created_at',
  ],
  elections: [
    'id',
    'name',
    'description',
    'status',
    'start_date',
    'end_date',
    'logo_url',
    'primary_color',
    'secondary_color',
    'results_published',
    'created_at',
  ],
  positions: ['id', 'election_id', 'name', 'description', 'sort_order', 'created_at'],
  candidates: ['id', 'position_id', 'name', 'photo', 'manifesto', 'sort_order', 'created_at'],
  votes: [
    'id',
    'election_id',
    'position_id',
    'candidate_id',
    'voter_hash',
    'receipt_hash',
    'vote_type',
    'created_at',
  ],
  audit_logs: ['id', 'admin_id', 'admin_code', 'action', 'details', 'ip_address', 'created_at'],
  announcements: ['id', 'title', 'content', 'is_active', 'priority', 'created_at'],
  voter_election_access: ['id', 'voter_id', 'election_id'],
};

const TABLE_SCHEMAS = {
  users: `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      code VARCHAR(10) NOT NULL UNIQUE,
      password VARCHAR(255) DEFAULT NULL,
      role ENUM('admin','voter') DEFAULT 'voter',
      has_voted TINYINT(1) DEFAULT 0,
      totp_secret VARCHAR(255) DEFAULT NULL,
      totp_enabled TINYINT(1) DEFAULT 0,
      pin VARCHAR(255) DEFAULT NULL,
      email VARCHAR(255) DEFAULT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  elections: `
    CREATE TABLE IF NOT EXISTS elections (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(200) NOT NULL,
      description TEXT,
      status ENUM('upcoming','active','closed') DEFAULT 'upcoming',
      start_date DATETIME,
      end_date DATETIME,
      logo_url VARCHAR(500) DEFAULT NULL,
      primary_color VARCHAR(7) DEFAULT NULL,
      secondary_color VARCHAR(7) DEFAULT NULL,
      results_published TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  positions: `
    CREATE TABLE IF NOT EXISTS positions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      election_id INT NOT NULL,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      sort_order INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE
    )
  `,
  candidates: `
    CREATE TABLE IF NOT EXISTS candidates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      position_id INT NOT NULL,
      name VARCHAR(100) NOT NULL,
      photo VARCHAR(500) DEFAULT '/images/placeholder.png',
      manifesto TEXT,
      sort_order INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE
    )
  `,
  votes: `
    CREATE TABLE IF NOT EXISTS votes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      election_id INT NOT NULL,
      position_id INT NOT NULL,
      candidate_id INT NOT NULL,
      voter_hash VARCHAR(255) NOT NULL,
      receipt_hash VARCHAR(255) DEFAULT NULL,
      vote_type ENUM('yes','no') DEFAULT 'yes',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE,
      FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE,
      FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
    )
  `,
  audit_logs: `
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      admin_id INT,
      admin_code VARCHAR(10),
      action VARCHAR(100) NOT NULL,
      details TEXT,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  announcements: `
    CREATE TABLE IF NOT EXISTS announcements (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      content TEXT,
      is_active TINYINT(1) DEFAULT 1,
      priority ENUM('low','medium','high') DEFAULT 'medium',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  voter_election_access: `
    CREATE TABLE IF NOT EXISTS voter_election_access (
      id INT AUTO_INCREMENT PRIMARY KEY,
      voter_id INT NOT NULL,
      election_id INT NOT NULL,
      FOREIGN KEY (voter_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE,
      UNIQUE KEY unique_access (voter_id, election_id)
    )
  `,
  password_reset_tokens: `
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      token VARCHAR(64) NOT NULL UNIQUE,
      expires_at DATETIME NOT NULL,
      used TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `,
};

const MIGRATIONS = [
  { table: 'users', column: 'password', definition: 'VARCHAR(255) DEFAULT NULL' },
  { table: 'users', column: 'totp_secret', definition: 'VARCHAR(255) DEFAULT NULL' },
  { table: 'users', column: 'totp_enabled', definition: 'TINYINT(1) DEFAULT 0' },
  { table: 'users', column: 'pin', definition: 'VARCHAR(255) DEFAULT NULL' },
  { table: 'users', column: 'email', definition: 'VARCHAR(255) DEFAULT NULL' },
  { table: 'elections', column: 'logo_url', definition: 'VARCHAR(500) DEFAULT NULL' },
  { table: 'elections', column: 'primary_color', definition: 'VARCHAR(7) DEFAULT NULL' },
  { table: 'elections', column: 'secondary_color', definition: 'VARCHAR(7) DEFAULT NULL' },
  { table: 'elections', column: 'results_published', definition: 'TINYINT(1) DEFAULT 0' },
  { table: 'candidates', column: 'sort_order', definition: 'INT DEFAULT 0' },
  { table: 'votes', column: 'receipt_hash', definition: 'VARCHAR(255) DEFAULT NULL' },
  { table: 'votes', column: 'vote_type', definition: "ENUM('yes','no') DEFAULT 'yes'" },
];

async function addColumn(table, column, definition) {
  if (!SAFE_TABLES.includes(table)) throw new Error(`Invalid table: ${table}`);
  if (!SAFE_COLUMNS[table] || !SAFE_COLUMNS[table].includes(column))
    throw new Error(`Invalid column: ${column} for table ${table}`);
  const validDef = definition.replace(/[^A-Za-z0-9_(),\s'".\\-]/g, '');
  const [cols] = await db.query(`SHOW COLUMNS FROM \`${table}\` LIKE ?`, [column]);
  if (cols.length === 0) {
    await db.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${validDef}`);
    return true;
  }
  return false;
}

async function createTables() {
  const tableOrder = [
    'users',
    'elections',
    'positions',
    'candidates',
    'votes',
    'audit_logs',
    'announcements',
    'voter_election_access',
    'password_reset_tokens',
  ];
  for (const table of tableOrder) {
    await db.query(TABLE_SCHEMAS[table]);
  }
}

async function runMigrations() {
  for (const m of MIGRATIONS) {
    await addColumn(m.table, m.column, m.definition);
  }
  const optionalTables = [
    'audit_logs',
    'announcements',
    'voter_election_access',
    'password_reset_tokens',
  ];
  for (const table of optionalTables) {
    try {
      await db.query(TABLE_SCHEMAS[table]);
    } catch {
      /* table may already exist */
    }
  }
}

async function createAdminUser(adminPassword) {
  const bcrypt = require('bcryptjs');
  const { generateCode } = require('../utils');
  const hashedPassword = await bcrypt.hash(adminPassword, 10);
  const adminCode = generateCode(8);
  await db.query('INSERT INTO users (code, password, role) VALUES (?, ?, ?)', [
    adminCode,
    hashedPassword,
    'admin',
  ]);
  return adminCode;
}

async function autoSetup() {
  try {
    const [tables] = await db.query("SHOW TABLES LIKE 'users'");
    if (tables.length > 0) {
      const [count] = await db.query('SELECT COUNT(*) as cnt FROM users WHERE role = "admin"');
      if (count[0].cnt > 0) {
        await runMigrations();
        return;
      }
    }

    await createTables();

    const adminPassword = process.env.ADMIN_PASSWORD;
    if (adminPassword) {
      await createAdminUser(adminPassword);
    }
  } catch (err) {
    console.error('Auto-setup error:', err.message);
  }
}

async function migrateDB() {
  await runMigrations();
}

module.exports = {
  autoSetup,
  migrateDB,
  createTables,
  runMigrations,
  SAFE_TABLES,
  SAFE_COLUMNS,
};
