/**
 * Mongoose model User.
 *
 * @author Anders Jonsson
 * @version 1.0.0
 */

import bcrypt from 'bcrypt'
import createError from 'http-errors'
import mongoose from 'mongoose'
import validator from 'validator'
import { Cryptography } from '../../utils/Cryptography.js'

const cryptography = new Cryptography(process.env.CRYPTO_ALGORITHM, process.env.CRYPTO_SECURITY_KEY, process.env.CRYPTO_INIT_VECTOR)

const { isEmail } = validator

// Create a schema.
const schema = new mongoose.Schema({
  firstname: {
    type: String,
    required: [true, 'First name is required.'],
    minLength: [1, 'The first name must be of minimum length 1 characters.'],
    maxLength: [256, 'The first name must be of maximum length 256 characters.'],
    trim: true,
    /**
     * Encrypt field on set.
     *
     * @param {string} value - The value to encrypt for db.
     * @returns {string} - Encrypted value.
     */
    set: value => cryptography.encrypt(value),
    /**
     * Decrypt field on get.
     *
     * @param {string} value - The value from db to decrypt.
     * @returns {string} - Decrypted value.
     */
    get: value => cryptography.decrypt(value)
  },
  lastname: {
    type: String,
    required: [true, 'Last name is required.'],
    minLength: [1, 'The last name must be of minimum length 1 characters.'],
    maxLength: [256, 'The last name must be of maximum length 256 characters.'],
    trim: true,
    /**
     * Encrypt field on set.
     *
     * @param {string} value - The value to encrypt for db.
     * @returns {string} - Encrypted value.
     */
    set: value => cryptography.encrypt(value),
    /**
     * Decrypt field on get.
     *
     * @param {string} value - The value from db to decrypt.
     * @returns {string} - Decrypted value.
     */
    get: value => cryptography.decrypt(value)
  },
  email: {
    type: String,
    required: [true, 'Email address is required.'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      /**
       * Validate the email as a valid email.
       *
       * @param {string} enteredEmail - The email entered and sent in the request.
       * @returns {boolean} - Is email valid.
       */
      validator: function (enteredEmail) {
        return isEmail(cryptography.decrypt(enteredEmail))
      },
      message: 'Please provide a valid email address.'
    },
    maxLength: [254, 'The email must be of maximum length 254 characters.'],
    /**
     * Encrypt field on set.
     *
     * @param {string} value - The value to encrypt for db.
     * @returns {string} - Encrypted value.
     */
    set: value => cryptography.encrypt(value),
    /**
     * Decrypt field on get.
     *
     * @param {string} value - The value from db to decrypt.
     * @returns {string} - Decrypted value.
     */
    get: value => cryptography.decrypt(value)
  },
  isAdmin: {
    type: Boolean
  },
  password: {
    type: String,
    minLength: [10, 'The password must be of minimum length 10 characters.'],
    maxLength: [256, 'The password must be of maximum length 256 characters.'],
    required: [true, 'Password is required.']
  },
  permissionLevel: Number
}, {
  timestamps: true,
  toJSON: {
    getters: true,
    /**
     * Performs a transformation of the resulting object to remove sensitive information.
     *
     * @param {object} doc - The mongoose document which is being converted.
     * @param {object} ret - The plain object representation which has been converted.
     */
    transform: function (doc, ret) {
      delete ret._id
      delete ret.__v
    },
    virtuals: true // ensure virtual fields are serialized
  }
})

schema.virtual('id').get(function () {
  return this._id.toHexString()
})

// Salts and hashes password before save.
schema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next()

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12)
})

/**
 * Authenticates a user.
 *
 * @param {string} username - Users username.
 * @param {string} password - Users password.
 * @returns {Promise<Auth>} - Promise for the user-object from db.
 */
schema.statics.authenticate = async function (username, password) {
  const user = await this.findOne({ username })

  // If no user found or password is wrong, throw an error.
  if (!user || !(await bcrypt.compare(password, user.password))) {
    throw createError(401)
  }

  // User found and password correct, return the user.
  return user
}

// Create a model using the schema.
export const Auth = mongoose.model('Auth', schema)
