const config = require('../config.json');
const mysql = require('mysql2/promise');
const { Sequelize } = require('sequelize');

module.exports = db = {};

initialize();

async function initialize() {
    try {
        const { host, port, user, password, database } = config.database;
        
        // 1. First test basic connection
        const connection = await mysql.createConnection({ 
            host, 
            port, 
            user, 
            password,
            insecureAuth: true // Add if using older MySQL auth
        });
        
        // 2. Create database if needed
        await connection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\`;`);
        await connection.end();

        // 3. Connect Sequelize
        const sequelize = new Sequelize(database, user, password, { 
            host,
            dialect: 'mysql',
            dialectOptions: {
                connectTimeout: 10000
            },
            logging: console.log // Enable to see SQL queries
        });

        // 4. Initialize models
        db.Account = require('../accounts/account.model')(sequelize);
        db.RefreshToken = require('../accounts/refresh-token.model')(sequelize);

        // 5. Setup relationships
        db.Account.hasMany(db.RefreshToken, { onDelete: 'CASCADE' });
        db.RefreshToken.belongsTo(db.Account);

        // 6. Sync models
        await sequelize.authenticate();
        await sequelize.sync({ alter: true });
        console.log('Database synchronized');
        
    } catch (err) {
        console.error('Database initialization failed:', err);
        process.exit(1);
    }
}