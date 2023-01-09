import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export const register = async (req, res) => {
    try {
        const {firstname, lastname, email, password} = req.body;
        const salt = await bcrypt.genSalt();
        const encryptedPassword = await bcrypt.hash(password, salt);
        const newUser = await User.create({
            firstname,
            lastname,
            email,
            password: encryptedPassword
        })
        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
    } catch (err) {
        res.status(500).json({error: err.message});
    }
}

export const login = async (req, res) => {
    try {
        const{email, password} = req.body;

        const user = await User.findOne({
            email: email
        });

        if(!user) return res.status(400).json({msg: 'Invalid Email/Password'});

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if(isPasswordValid) {
            const token = jwt.sign({id: user._id}, process.env.JWT_SECRET);
            user.password = '***';
            res.status(200).json({token, user});
        } else {
            res.status(400).json({msg: 'Invalid Credentials'})
        }
    } catch(err) {
        res.status(500).json({error: err.message})
    }
}
