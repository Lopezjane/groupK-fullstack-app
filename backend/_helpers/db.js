const config = require('../config.json');
const { Sequelize } = require('sequelize');

module.exports = db = {};

// Determine which environment config to use
const env = process.env.NODE_ENV || 'development';
const envConfig = config[env];

if (!envConfig) {
    console.error(`No configuration found for environment: ${env}`);
    process.exit(1);
}

initialize();

async function initialize() {
    try {
        const { dialect, host, port, user, password, database } = envConfig.database;
        
        console.log(`Connecting to PostgreSQL database at ${host}:${port}/${database}`);
        
        // Connect to PostgreSQL using Sequelize
        const sequelize = new Sequelize(database, user, password, { 
            host,
            port,
            dialect: dialect || 'postgres',
            dialectOptions: {
                ssl: {
                    require: true,
                    rejectUnauthorized: false
                }
            },
            logging: console.log // Enable to see SQL queries
        });

        // Initialize models
        db.Account = require('../accounts/account.model')(sequelize);
        db.RefreshToken = require('../accounts/refresh-token.model')(sequelize);

        // Setup relationships
        db.Account.hasMany(db.RefreshToken, { onDelete: 'CASCADE' });
        db.RefreshToken.belongsTo(db.Account);

        // Sync models - create tables if they don't exist
        await sequelize.authenticate();
        console.log('Connected to PostgreSQL database successfully.');
        
        await sequelize.sync({ alter: true });
        console.log('Database schema synchronized');
        
    } catch (err) {
        console.error('Database initialization failed:', err);
        process.exit(1);
    }
}