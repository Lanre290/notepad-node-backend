const express = require('express');
const app = express();
const cors = require('cors');
import dotenv from 'dotenv';
import { Request } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';


dotenv.config(); 


const PORT:any = process.env.PORT || 5000;
const SQL_PORT:any = process.env.DB_PORT;
const FRONTEND_URL:any = process.env.FRONTEND_URL;


interface corsInterface {
    origin:string;
    methods:string[];
    allowedHeaders?:string[];
}

const corsOption:corsInterface = {
    origin: FRONTEND_URL,
    methods: ['GET', 'POST', 'PUT', 'DELETE']
}

const pool = new Pool({
    user: process.env.DB_USER,       
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: SQL_PORT,
});

const checkTableExists = async (tableName: string) => {
    try {
        const query = `
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = $1
        );
        `;
        const result = await pool.query(query, [tableName]);
        return result.rows[0].exists;
    } catch (error) {
        console.error("Error checking if table exists:", error);
        throw error;
    }
};

const ensureTableExists = async (tableName: string) => {
const tableExists = await checkTableExists(tableName);

    if (!tableExists) {
        try {
        let createTableQuery = ''
        if(tableName == 'users'){
            createTableQuery = `
                CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(40) NOT NULL,
                pwd TEXT
                );
            `;
        }
        else if (tableName == 'notes'){
            createTableQuery = `
                CREATE TABLE notes (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                "user" INT NOT NULL,
                content TEXT,
                timestamp INT
                );
            `;
        }
        await pool.query(createTableQuery);
        console.log(`Table '${tableName}' created successfully.`);
        } catch (error) {
        console.error("Error creating table:", error);
        throw error;
        }
    } else {
        console.log(`Table '${tableName}' already exists.`);
    }
};

const encryptPassword = async (password:string) => {
    let saltRounds:number | any = process.env.SALT_ROUNDS;
    try {
        bcrypt.hash(password, saltRounds, (err:any, hash:any) => {
            if(err){
                return 'Error';
            }
            else{
                return hash
            }
        });
    } catch (error) {
        console.error('Error encrypting password.');
    }
}

const verifyPassword = async (plainTextPassword:string, hashedPassword:string) => {
    try {
        const match = await bcrypt.compare(plainTextPassword, hashedPassword);
        if (match) {
            console.log('Passwords match!');
        } else {
            console.log('Passwords do not match!');
        }
        return match;
    } catch (error) {
        return "Error verifying passwordds.";
    }
};

ensureTableExists('users');
ensureTableExists('notes');

//middlewares
app.use(cors(corsOption));
app.use(express.json());
app.use(express.urlencoded({extended: true}));


app.post('/api/auth/signup', async (req:Request, res:any) => {
  const {name, email, pwd} = req.body;

  if(!name || !email || !pwd){
    res.status(401).json({'error': 'Unexpected request.'});
  }
  else{
    try {
        const emailExistsQuery:any = await pool.query('SELECT COUNT(*) FROM users WHERE email=$1',[email]);

        let emailExistsNo = emailExistsQuery.rows[0].count;

        if(emailExistsNo > 0){
            res.status(409).json({'error': 'Email already exists.'});
        }
        else{
            const query = `INSERT INTO users (name, email, pwd) VALUES ($1, $2, $3)`;

            let encrytedPassword = await encryptPassword(pwd);

            let queryResult = await pool.query(query, [name, email, encrytedPassword]);
            
            res.status(200).json({data: queryResult});
        }
    } catch (error) {
        res.status(500).json({error: 'Internal server error', errorData: error})
    }
  }
})

app.post('/api/auth/login', async (req:Request, res:any) => {
  const {email, pwd} = req.body;

  if(!email || !pwd){
    res.status(401).json({'error': 'Unexpected response.'});
  }
  else{
    let emailExistsQuery:any = await pool.query('SELECT COUNT(*) FROM users WHERE email=$1',[email]);

    let emailExistsNo = emailExistsQuery.data.rows.count;
    if(emailExistsNo < 1){
        res.status(404, {'error': "Email does not exist."});
    }
    else{
        let userData = await pool.query('SELECT * from users WHERE email=$1', [email]);

        
        
    }
  }
})


// "nodemon --exec ts-node src/script.ts"

app.listen(PORT, () => {
    console.log(`server is listening on port: ${PORT}`);
})