/**
 * The AccountController.
 *
 * @author Anders Jonsson
 * @version 1.0.0
 */

import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import { Auth } from '../models/auth.js'

/**
 * Encapsulates a controller.
 */
export class AccountController {
  /**
   * Authenticates a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async login (req, res, next) {
    try {
      const user = await Auth.authenticate(req.body.username, req.body.password)
      const formattedUser = user.toJSON()

      const payload = {
        sub: formattedUser.id,
        x_is_admin: formattedUser.isAdmin
      }

      // Create the access token with the shorter lifespan.
      const accessToken = jwt.sign(payload, Buffer.from(process.env.ACCESS_TOKEN_SECRET, 'base64'), {
        algorithm: 'RS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
      })

      // Authentication successful.
      res
        .status(200)
        .json({
          access_token: accessToken
        })
    } catch (error) {
      // Authentication failed or server-error.
      const err = error

      err.cause = error
      next(err)
    }
  }

  /**
   * Registers a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async register (req, res, next) {
    try {
      const user = new Auth({
        isAdmin: false,
        password: req.body.password,
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        email: req.body.email
      })

      await user.save()

      // User successfully registered.
      res
        .status(201)
        .json({ id: user.id })
    } catch (error) {
      let err = error

      if (err.code === 11000) {
        // Duplicated keys.
        err = createError(409)
        err.cause = error
      } else if (error.name === 'ValidationError') {
        // Validation error(s).
        err = createError(400)
        err.cause = error
      }

      next(err)
    }
  }

  // TODO: Add Patch/Put/Delete.
}
