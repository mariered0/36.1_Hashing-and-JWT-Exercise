/** User class for message.ly */
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const jwt = require("jsonwebtoken");
const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const { authenticateJWT, ensureLoggedIn, ensureAdmin } = require("../middleware/auth");

/** User of the site. */

class User {
  // constructor(username, password, first_name, last_name, phone, join_at, last_login_at){
  //   this.username = username;
  //   this.password = password;
  //   this.first_name = first_name;
  //   this.last_name = last_name;
  //   this.phone = phone;
  //   this.join_at = join_at;
  //   this.last_login_at;
  // }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {

      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

      const results = await db.query(`
      INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone, join_at, last_login_at]);
      return results.rows[0];
    }
   


  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
      const results = await db.query(
        `SELECT password
         FROM users
         WHERE username = $1`,
        [username]);
      const user = results.rows[0];
      return user && await bcrypt.compare(password, user.password);
      }
    
    
   

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
      SET last_login_at = current_timestamp
      WHERE username = $1
      RETURNING username`,
      [username]
      );
    if (!result.rows[0]){
      throw new ExpressError("User not found", 400);
    }
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(`
    SELECT username, first_name, last_name, phone
    FROM users`);
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1`,
      [username])
    const u = results.rows[0];
    if (!u){
      throw new ExpressError("User not found", 404);
    }
    return u;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const mesResult = await db.query(
      `SELECT id, body, sent_at, read_at
      FROM messages
      WHERE from_username = $1`,
      [username]);
    const toUserResult = await db.query(`
    SELECT u.username, u.first_name, u.last_name, u.phone
    FROM users AS u
    JOIN
    messages AS m
    ON m.to_username = u.username
    WHERE m.from_username = $1`,
    [username]);

    if (mesResult.rows.length === 0) {
      throw new ExpressError(`No messages from user, ${username}`, 404);
    }

    const messages = mesResult.rows;
    const toUsers = toUserResult.rows[0];

    messages.map(message => message['to_user'] = toUsers);

    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const mesResult = await db.query(
      ` SELECT id, body, sent_at, read_at
      FROM messages
      WHERE to_username = $1`,
      [username]);
    const fromUserResult = await db.query(
      `SELECT u.username, u.first_name, u.last_name, u.phone
      FROM users AS u
      JOIN
      messages AS m
      ON m.from_username = u.username
      WHERE m.to_username = $1`,
      [username]);

    if (mesResult.rows.length === 0) {
      throw new ExpressError(`No messages to user, ${username}`, 404);
    }
    const messages = mesResult.rows;
    const fromUsers = fromUserResult.rows[0];
    

    messages.map(message => message['from_user'] = fromUsers);
    console.log(messages)
    return messages;
  }
  
}


module.exports = User;