const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");
const Message = require("../models/message");

//routes: messages/

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/


//don't know how to authenticate multiple users
router.get('/:id', ensureLoggedIn, async (req, res, next) => {
  try{
    const username = req.user.username;
    const msg = await Message.get(req.params.id);
    if (msg.to_user.username !== username && msg.from_user.username !== username){
      throw new ExpressError("Cannot read this message", 401);
    }

    return res.json({ message: msg });

  }catch(e){
    return next (e);
  }
    
})


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async (req, res, next) => {
  try{
    console.log('to_username', req.body.to_username)
    console.log('body', req.body.body)
    const message = await Message.create({
      from_username: req.body.from_username,
      to_username: req.body.to_username,
      body: req.body.body
    })
    console.log('message', message);
    return res.json({ message: message })
  } catch(e){
    return next (e);
  }
})



/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post('/:id/read', ensureLoggedIn, async (req, res, next) => {
  try{
    const user = await db.query(`
    SELECT u.username
    FROM users AS u
    JOIN messages AS m ON u.username = m.to_username
    WHERE m.id = $1`,
    [req.params.id]);

    const msg = await Message.get(req.params.id);
    
    if (msg.to_user.username !== username) {
      throw new ExpressError("Cannot set this message to read", 401);
    }
    
  
    const message = Message.markRead(req.params.id);
    return res.json({ message })
  }
  catch(e){
    return next(e)
  }
})



 module.exports = router;

