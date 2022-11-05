/**
 * The routes.
 *
 * @author Anders Jonsson
 * @version 1.0.0
 */

import express from 'express'
import createError from 'http-errors'
import { router as accountRouter } from './account-router.js'

export const router = express.Router()

router.get('/', (req, res) => res.json({ message: 'Welcome to the auth-service!' }))
router.use('/', accountRouter)

// Catch 404 (ALWAYS keep this as the last route).
router.use('*', (req, res, next) => next(createError(404)))
