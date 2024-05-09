import User from '../models/user.model.js';
import bycryptjs from 'bcryptjs';
import { errorHandler } from '../utils/error.js';
import jwt from 'jsonwebtoken';

export const signUp = async (req, res, next) => {
    const { username, email, password} = req.body;
    const hashPassword = bycryptjs.hashSync(password, 10);
    const newUser = new User({ 
        username,
        email,
        password: hashPassword 
    });
    try {
        await newUser.save();
        res.status(201).json("User created successfully");
    } catch(error) {
        next(error);
    }
}

export const signIn = async (req, res, next) => {
    const {email, password} = req.body;
    try {
        const validUser = await User.findOne({email});
        if (!validUser) {
            return next(errorHandler(404, "User not found!"));
        }

        const validPassword = bycryptjs.compareSync(password, validUser.password);
        if (!validPassword) {
            return next(errorHandler(401, "Wrong credentials!"));
        }
        const {password: pass, ...rest} = validUser._doc;
        const token = jwt.sign({id: validUser._id}, process.env.JWT_SECRET);
        res.cookie('access_token', token, {httpOnly: true, expires: new Date(Date.now() + 24 * 60 * 60)})
            .status(200)
            .json(rest);

    } catch(error) {
        next(error);
    }

}