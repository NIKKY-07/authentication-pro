const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "rishik",
  database: "authentication_db",
});

db.connect((err) => {
  if (err) {
    console.log("Database connection failed");
    return;
  }

  console.log("MySQL connected successfully");
});

module.exports = db;
