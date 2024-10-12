const express = require('express');
const app = express();
const cors = require('cors');
import dotenv from 'dotenv';
import { Request } from 'express';
import { Pool } from 'pg';

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
                pwd LONGTEXT
                );
            `;
        }
        else if (tableName == 'notes'){
            createTableQuery = `
                CREATE TABLE notes (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                user INT(30) NOT NULL,
                content LONGTEXT,
                timestamp INT(40),
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
    const emailExists = await pool.query('SELECT COUNT(*) FROM users WHERE email=$1',[email]);

    console.log(emailExists);
  }
})


app.listen(PORT, () => {
    console.log(`server is listening on port: ${PORT}`);
})