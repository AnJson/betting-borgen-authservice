/**
 * The starting point of the application.
 *
 * @author Anders Jonsson
 * @version 1.0.0
 */

import express from 'express'
import helmet from 'helmet'
import logger from 'morgan'
import cors from 'cors'
// import { corsOptions } from './config/cors.js'
import { router } from './routes/router.js'
import { connectDB } from './config/mongoose.js'
import { rateLimiter } from './config/rate-limit.js'

try {
  await connectDB()

  const app = express()

  // Add helmet for app-security.
  app.use(helmet())

  // Allow requests from other servers.
  app.use(cors())

  // Set up a morgan logger using the dev format for log entries.
  app.use(logger('dev'))

  // Parse requests of the content type application/json.
  app.use(express.json())

  // Apply the rate limiting middleware on requests to the login endpoint.
  app.use('/login', rateLimiter)

  // Register routes.
  app.use('/', router)

  // Error handler.
  app.use(function (err, req, res, next) {
    err.status = err.status || 500

    if (err.status === 400) {
      err.message = 'The request cannot or will not be processed due to something that is perceived to be a client error (for example, validation error).'
    } else if (err.status === 401) {
      err.message = 'Credentials invalid or not provided.'
    } else if (err.status === 409) {
      err.message = 'The username and/or email address is already registered.'
    } else if (err.status === 500) {
      err.message = 'An unexpected condition was encountered.'
    }

    if (req.app.get('env') !== 'development') {
      return res
        .status(err.status)
        .json({
          status: err.status,
          message: err.message
        })
    }

    // Development only!
    // Only providing detailed error in development.
    return res
      .status(err.status)
      .json({
        status: err.status,
        message: err.message,
        cause: err.cause
          ? {
              status: err.cause.status,
              message: err.cause.message,
              stack: err.cause.stack
            }
          : null,
        stack: err.stack
      })
  })

  // Starts the HTTP server listening for connections.
  app.listen(process.env.PORT, () => {
    console.log(`Server running at http://localhost:${process.env.PORT}`)
    console.log('Press Ctrl-C to terminate...')
  })
} catch (err) {
  console.error(err)
  process.exitCode = 1
}
