const express = require("express");
const app = express();
const cors = require("cors");
import dotenv from "dotenv";
import { NextFunction, Request, Response } from "express";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');


const redisClient = redis.createClient();

dotenv.config();

const PORT: any = process.env.PORT || 5000;
const SQL_PORT: any = process.env.DB_PORT;
const FRONTEND_URL: any = process.env.FRONTEND_URL;
const secretKey = process.env.SECRET_KEY;

interface corsInterface {
  origin: string;
  methods: string[];
  allowedHeaders?: string[];
}

const corsOption: corsInterface = {
  origin: FRONTEND_URL,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: SQL_PORT,
});

//middlewares
app.use(cors(corsOption));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true}
}));

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
      let createTableQuery = "";
      if (tableName == "users") {
        createTableQuery = `
                CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(40) NOT NULL,
                pwd TEXT
                );
            `;
      } else if (tableName == "notes") {
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

const encryptPassword = async (password: string) => {
  let saltRounds: number | any = process.env.SALT_ROUNDS;
  try {
    bcrypt.hash(password, saltRounds, (err: any, hash: any) => {
      if (err) {
        return "Error";
      } else {
        return hash;
      }
    });
  } catch (error) {
    console.error("Error encrypting password.");
  }
};

const verifyPassword = async (
  plainTextPassword: string,
  hashedPassword: string
) => {
  try {
    const match = await bcrypt.compare(plainTextPassword, hashedPassword);
    return match;
  } catch (error) {
    return "Error verifying passwordds.";
  }
};

const sendOTP = async (userId: number, email: string, name: string, otp:number) => {
  try {

    const mailOptions = {
      from: "your-email@example.com",
      to: email,
      subject: "Verify your Identity",
      html: `Hello ${
        name.split(" ").length > 1 ? name.split(" ")[1] : name.split(" ")[0]
      }, Confirm your email.
                    OTP CODE
                    ${otp}
                    Please enter the following OTP to complete your verification process, if you did not make this request, you can safely ignore this email.



                    Your friendly neighborhood TechBro - BroCode. 💝 
                    `,
    };

    transporter.sendMail(mailOptions, async (error: any, info: any) => {
      if (error) {
        console.log('error');
      } else {
        return true
      }
    });
  } catch (error) {
    return "Error sending mail";
  }
};

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: process.env.MAIL_PORT,
  secure: true,
  auth: {
    user: process.env.MAIL_USERNAME,
    pass: process.env.MAIL_PASSWORD,
  },
});

const authenticateToken = (
  req: Request | any,
  res: any,
  next: NextFunction
) => {
  const token = (req.headers.authorization as string).split(" ")[1];

  if (!token) {
    res.status(401).json({ sucess: false, error: "Please provide a token." });
  }

  jwt.verify(token, secretKey, (err: any, decoded: any) => {
    if (err) {
      res.status(401).json({ sucess: false, error: "Error." });
    } else {
      req.userId = decoded.id;
    }

    next();
  });
};

ensureTableExists("users");
ensureTableExists("notes");

app.post(
  "/api/auth/signup",
  async (req: Request | any, res: any) => {
    const { name, email, pwd } = req.body;

    console.log(req.body);

    if (!name || !email || !pwd) {
      res.status(401).json({ error: "Unexpected request." });
    } else {
      try {
        const emailExistsQuery: any = await pool.query(
          "SELECT COUNT(*) FROM users WHERE email=$1",
          [email]
        );

        let emailExistsNo = emailExistsQuery.rows[0].count;

        if (emailExistsNo > 0) {
          res.status(409).json({ error: "Email already exists." });
        } else {
          const query = `INSERT INTO users (name, email, pwd) VALUES ($1, $2, $3) RETURNING id,email,name`;

          let encrytedPassword = await encryptPassword(pwd);

          let queryResult = await pool.query(query, [
            name,
            email,
            encrytedPassword,
          ]);
          const userId: number = queryResult.rows[0].id;
          const userEmail: string = queryResult.rows[0].email;
          const username: string = queryResult.rows[0].name;

          const token = jwt.sign({ id: userId }, secretKey, {
            expiresIn: "3h",
          });

          const user = {
            id: userId,
            email: userEmail,
            name: username,
          };

          res.status(200).json({ success: true, data: user, token: token });
          const otp = Math.floor(1000 + Math.random() * 9000);
          sendOTP(userId, userEmail, username, otp);
          req.session.otp = otp;
          req.session.user = user;
          req.id = userId;
          req.email = userEmail;
          req.name = username;
        }
      } catch (error) {
        res
          .status(500)
          .json({ error: "Internal server error", errorData: error });
      }
    }
  }
);

app.post("/api/auth/login", async (req: Request, res: Response) => {
  try {
    const { email, pwd } = req.body;

    if (!email || !pwd) {
      res.status(401).json({ error: "Unexpected request." });
    } else {
      let emailExistsQuery: any = await pool.query(
        "SELECT COUNT(*) FROM users WHERE email=$1",
        [email]
      );

      let emailExistsNo = emailExistsQuery.data.rows.count;
      if (emailExistsNo < 1) {
        res.status(404).json({ error: "Email does not exist." });
      } else {
        let userData = await pool.query("SELECT * FROM users WHERE email=$1", [
          email,
        ]);

        interface userInterface {
          name: string;
          email: string;
          pwd: string;
        }
        let user: userInterface = userData.rows[0];

        try {
          const match = await bcrypt.compare(pwd, user.pwd);
          if (match) {
            res.status(200).json({success: true});
          } else {
            res
              .status(409)
              .json({ success: false, error: "Incorrect details provided." });
          }
        } catch (error) {
          res
            .status(400)
            .json({ sucess: false, error: "Failed to load resource." });
        }

        res.status(200).json({ data: userData });
      }
    }
  } catch (error) {}
});

app.post('/otp', function (req:Request | any, res:any) {
  const userId = req.session.user.id;
  const userEmail = req.session.user.email;
  const username = req.session.user.name;

  if(!userId || !userEmail || !username){
    res.status(401).json({'error': 'Unauthorized acess.'});
  }
  const otp = Math.floor(1000 + Math.random() * 9000);
  sendOTP(userId, userEmail, req.user.name, otp);
  req.session.otp = otp;
});

app.post('/verify-otp', function (req:Request | any, res:any) {
  let {otp} = req.body;

  if(otp != req.session.otp){
    res.status(409).json({'error': 'Incorrect otp entered.', 'otp': req.session.otp});
  }
  else{
    res.status(200).json({success: true});
  }
});


app.listen(PORT, () => {
  console.log(`server is listening on port: ${PORT}`);
});
