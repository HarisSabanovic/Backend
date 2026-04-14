import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "../lib/db.js"


//Registrering
export async function register (req,res) {
    try {
         const {username, email, password} = req.body;
         const missingFields = [];

            if (!username) missingFields.push("username");
            if (!email) missingFields.push("email");
            if (!password) missingFields.push("password");

            if (missingFields.length > 0) {
            return res.status(400).json({
                message: `${missingFields.join(", ")} ${missingFields.length > 1 ? "are" : "is"} required`
            });
            }

                const existingUser = await pool.query(
                    "SELECT id FROM users WHERE email = $1",
                    [email]
                );

                if (existingUser.rows.length > 0) {
                return res.status(409).json({
                    message: "Email already exists"
                });
                }

                const passwordHash = await bcrypt.hash(password, 10);

                const result = await pool.query(
                    `INSERT INTO users (username, email, password_hash)
                    VALUES ($1, $2, $3)
                    RETURNING id, username, email, created_at`,
                [username, email, passwordHash]
                );

                res.status(201).json({
                message: "User created successfully",
                user: result.rows[0]
                });
            } catch (error) {
                res.status(500).json({
                message: "Register failed",
                error: error.message
                });
    }
}