const sqlite3 = require('sqlite3').verbose();

class Database {
  constructor() {
    if (!Database.instance) {
      this.db = new sqlite3.Database('./database.db');
      Database.instance = this;
    }
    return Database.instance;
  }

  getConnection() {
    return this.db;
  }
}

const instance = new Database();
Object.freeze(instance);

module.exports = instance;