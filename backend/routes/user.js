const express = require("express");
const router = express.Router();
const bcrypt = require('bcrypt')
const {z, ZodError} = require('zod');
const {User} = require('../db/db');
const jwt = require('jsonwebtoken');

require("dotenv").config();
const SecretKey = process.env.MY_SECRET_KEY;

const {authenticateJwt} = require('../middleware/auth');

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
    const user = await User.findOne({ username: userName }); 
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

router.post("/signin", async (req, res) => {
    const { username, password } = req.body;
  
    const user = await User.findOne({ username });
  
    const isPasswordValid = await bcrypt.compare(password, user.password);
  
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password" });
    }
  
    if (!user) {
      return res.status(411).json({
        message: "User doesn't exist! Please Signup.",
      });
    }
  
    try {
      const userId = user._id;
      const token = jwt.sign({ user, userId }, SecretKey);
  
      return res.json({
        token,
      });
    } catch (error) {
      return res.status(411).json({
        message: "Error while logging in!",
      });
    }
  });

//   router.put("/", authenticateJwt, async (req, res) => {
//     const { password, firstName, lastName } = req.body;
//     await User.updateOne({ _id: req.userId }, password, firstName, lastName);
	
//     res.json({
//         message: "Updated successfully"
//     })
// })

const updateBody = z.object({
	password: z.string().optional(),
    firstName: z.string().optional(),
    lastName: z.string().optional(),
})

router.put("/", authenticateJwt, async (req, res) => {
    const { success } = updateBody.safeParse(req.body)
    if (!success) {
        res.status(411).json({
            message: "Error while updating information"
        })
    }

        const u =  await User.findByIdAndUpdate(req.user.userId , req.body);
        if (u) {
            res.json({ message: 'Updated successfully' });
          } else {
            res.status(404).json({ message: 'user not found' });
          }
        });


  
  
module.exports = router;
