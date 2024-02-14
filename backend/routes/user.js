const express = require("express");
const router = express.Router();
const bcrypt = require('bcrypt')
const {z, ZodError} = require('zod');
const {User} = require('../db/db');
const jwt = require('jsonwebtoken');

require("dotenv").config();
const SecretKey = process.env.MY_SECRET_KEY;

const signupSchema = z.object({
    username: z.string().email(),  
    firstName: z.string().max(30), 
    lastName: z.string().max(30),
    password: z.string().min(8)
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
            message: 'Password must contain at least one uppercase letter, one lowercase letter, one special character, and one number',
        }),
});

router.post('/signup', async (req, res) => {
    const userName = req.body.username;
    const user = await User.findOne({ username: userName }); // Corrected this line
    if (user) {
        return res.status(403).json({ message: 'User already exists' });
    } 
    try {
        const userData = signupSchema.parse(req.body);
        const hashedPassword = await bcrypt.hash(userData.password, 10)
        const newUser = new User({
            username: userData.username,
            firstName: userData.firstName, 
            lastName: userData.lastName, 
            password: hashedPassword
        });
        await newUser.save();
        const userId = newUser._id; 
        const token = jwt.sign({
            userId
        }, SecretKey);
    
        res.status(200).json({
            success: true, msg: "Signup Successful: New User Created", data: userData, token: token  
        });
    } catch (error) {
        if (error instanceof ZodError){
            res.status(400).json({ success: false, msg: 'Validation failed' });
        } else {
            console.error(error);
            res.status(500).json({ success: false, msg: 'Internal Server Error' });
        }
    }
});

module.exports = router;
