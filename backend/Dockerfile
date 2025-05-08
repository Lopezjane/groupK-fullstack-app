FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install all dependencies (production + dev)
RUN npm install

# Install specific required packages
RUN apk add --no-cache postgresql-client && \
    npm install && \
    npm install express dotenv body-parser cookie-parser cors rootpath && \
    npm install sequelize && \
    npm install pg pg-hstore && \
    npm install bcryptjs jsonwebtoken express-jwt joi && \
    npm install nodemailer swagger-ui-express yamljs && \
    npm install --save-dev nodemon && \

# Copy the rest of the application code
COPY . .

# Expose the app port
EXPOSE 4000

# Command to run the app with nodemon (for dev)
CMD ["npx", "nodemon", "server.js"]

# If you want production mode, replace the above CMD with:
# CMD ["node", "server.js"]
