const mysql = require('mysql2/promise');

const dbHost = process.env.MYSQL_HOST || process.env.DB_HOST || 'localhost';
const dbUser = process.env.MYSQL_USER || process.env.DB_USER || 'root';
const dbPass = process.env.MYSQL_PASSWORD || process.env.DB_PASSWORD || '';
const dbName = process.env.MYSQL_DATABASE || process.env.DB_NAME || 'biseco_vote';

const pool = mysql.createPool({
  host: dbHost,
  user: dbUser,
  password: dbPass,
  database: dbName,
  waitForConnections: true,
  connectionLimit: 10,
});

module.exports = pool;
