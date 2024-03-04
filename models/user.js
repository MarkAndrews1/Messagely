/** User class for message.ly */
const db = require("../db")
const ExpressError = require("../expressError");

const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config")


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    try{
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)

      const result = await db.query(
        `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
         VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp )
         RETURNING username, password, first_name, last_name, phone
        `, [username, hashedPassword, first_name, last_name, phone]
        )
  
        return result.rows[0]
    }catch(err){
      return next(err)
    }

  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    try{
      const result = await db.query(`
      SELECT password FROM users WHERE username = $1 
      `, [username])

      if(result.rows.length === 0){
        return false
      }

      const hashedPassword = result.rows[0].password
      const isValidPassword = await bcrypt.compare(password, hashedPassword)

      return isValidPassword
    }catch(err){
      return next(err)
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`
    UPDATE users 
    SET last_login_at = current_timestamp 
    WHERE username = $1 
    RETURNING username`, [username])
    if(!result.rows[0]){
      throw new ExpressError(`Couldn't find ${username}`, 404)
    }
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const result = await db.query(`
    SELECT username, first_name, last_name, phone 
    FROM users 
    ORDER BY username
    `)

    return result.rows
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
    const result = await db.query(`
    SELECT username, first_name, last_name, phone, join_at, last_login_at
    FROM users 
    WHERE username = $1`, [username])

    if(!result.rows[0]){
      throw new ExpressError(`Couldn't find ${username}`, 404)
    }

    return result.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const result = await db.query(`
    SELECT
    m.id,
    m.from_username,
    u.first_name,
    u.last_name,
    u.phone,
    m.body,
    m.sent_at,
    m.read_at
    FROM messages AS m
    INNER JOIN users AS u ON m.to_username = u.username
    WHERE to_username = $1
    `, [username])

    let messages = result.rows.map(m => ({
      id: m.id,
      body: m.body,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone },
        sent_at: m.sent_at,
        read_at: m.read_at
    }))

    return messages
   }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const result = await db.query(`
    SELECT
    m.id,
    m.from_username,
    u.first_name,
    u.last_name,
    u.phone,
    m.body,
    m.sent_at,
    m.read_at
    FROM messages AS m
    INNER JOIN users AS u ON m.from_username = u.username
    WHERE to_username = $1
    `, [username])

    let messages = result.rows.map(m => ({
      id: m.id,
      body: m.body,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone },
        sent_at: m.sent_at,
        read_at: m.read_at
    }))

    return messages
   }
}


module.exports = User;