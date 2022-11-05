/**
 * Cryptography module.
 *
 * @author Anders Jonsson
 * @version 1.0.0
 */

import { createCipheriv, createDecipheriv } from 'crypto'

/**
 * Encapsulating module for encryption and decryption with crypto.
 *
 */
export class Cryptography {
  /**
   * Encryption algorithm
   *
   * @type {string}
   */
  #algorithm

  /**
   * Init vector.
   *
   * @type {string}
   */
  #initVector

  /**
   * Cipher key.
   *
   * @type {string}
   */
  #securityKey

  /**
   * Set up Cryptography secrets and algorithm.
   *
   * @param {string} algorithm - The algorithm to use for encryption and decryption.
   * @param {string} securityKey - The key to encrypt/decrypt.
   * @param {string} initVector - The "salt" in the encryption.
   */
  constructor (algorithm, securityKey, initVector) {
    this.#algorithm = algorithm
    this.#securityKey = securityKey
    this.#initVector = initVector
  }

  /**
   * Encrypt message using nodejs crypto.
   *
   * @param {*} message - Message to encrypt.
   * @returns {string} - Encrypted string.
   */
  encrypt (message) {
    try {
      const cipher = createCipheriv(this.#algorithm, this.#securityKey, this.#initVector)
      let encryptedData = cipher.update(message, 'utf-8', 'hex')
      encryptedData += cipher.final('hex')

      return encryptedData
    } catch (error) {
      console.log(error)
    }
  }

  /**
   * Decrypt message using nodejs crypto.
   *
   * @param {*} encryptedMessage - Encrypted message to decrypt.
   * @returns {string} - Decrypted string.
   */
  decrypt (encryptedMessage) {
    try {
      const decipher = createDecipheriv(this.#algorithm, this.#securityKey, this.#initVector)
      let decryptedData = decipher.update(encryptedMessage, 'hex', 'utf-8')
      decryptedData += decipher.final('utf8')

      return decryptedData
    } catch (error) {
      console.log(error)
    }
  }
}
