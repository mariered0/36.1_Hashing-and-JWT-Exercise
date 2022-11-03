const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");

// const bcrypt = require("bcrypt");

const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
// //import middleware
const { authenticateJWT } = require("../middleware/auth");

const User = require("../models/user");



//The form of route: auth/...

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', authenticateJWT, async (req, res, next) => {
    try{
        const { username, password } = req.body;
        // if(!username || !password ){
        //     throw new ExpressError("Username/password is missing.", 400);
        // }
        const user = await User.authenticate(username, password);
        if(user){
            await User.updateLoginTimestamp(username);
            const token = jwt.sign({ username }, SECRET_KEY);
            return res.json({ username, token });
        }
        throw new ExpressError("Invalid username/password", 400);
    }catch(e){
        return next(e);
    }
})




/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post('/register', authenticateJWT , async (req, res, next) => {
    try{
        const { username, password, first_name, last_name, phone } = req.body;
        await User.register({username, password, first_name, last_name, phone});
        await User.authenticate(username, password);
        await User.updateLoginTimestamp(username);
        const token = jwt.sign({ username }, SECRET_KEY);
        return res.json({ token });
    }catch(e) {
        if (e.code === '23505') {
            return next(new ExpressError("Username taken. Please pick another.", 400));
        }
        return next(e);
    }
})

module.exports = router;