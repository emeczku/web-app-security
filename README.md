# web-app-security

I am a self-taught developer specializing in creating websites and web applications. When creating my latest commercial project, I asked AI and a web browser to provide security ideas for use in my application. I had to search a lot to find examples, links, etc., so now I've created this repository for all of you to reduce the time you spend searching all that stuff online. Please check each point 2 times by yourself as I am not a cybersecurity specialist, I just wanted to describe the points I used.

## Table of contents

1. [Frontend security](#frontend)
2. [Backend security](#backend)
  - [Express](#express)
3. Server security
  - Firewall - many web hosting providers provide their own firewalls
  - Bakcup - many hosting providers provide automatic backups
    - Wordpress - you can install free plugins from the dashboard to reduce the risk of not having them and keep them in a convenient place for you
  - Remove ability to login as root (you need to create a user with sudo permissions)
    - Reduced risk of mistakes
    - Increased accountability
    - Reduced risk of unauthorized access
  - SSL - many hosting providers provide free installation of Let's Encrypt
    - [Let's Encrypt - website](https://letsencrypt.org/)

## Frontend

## Backend

### Express

### HTTP Headers

```bash
  npm install helmet
```

Example

```javascript
const express = require("express");
const helmet = require("helmet");

const app = express();

app.use(helmet());
```

[Helmet npmjs.com](https://www.npmjs.com/package/helmet)

### CSURF

```bash
  npm install csurf
```

Example

```javascript
// Backend

var cookieParser = require('cookie-parser')
var csrf = require('csurf')
var bodyParser = require('body-parser')
var express = require('express')
 
// setup route middlewares
var csrfProtection = csrf({ cookie: true })
var parseForm = bodyParser.urlencoded({ extended: false })
 
// create express app
var app = express()
 
// parse cookies
// we need this because "cookie" is true in csrfProtection
app.use(cookieParser())
 
app.get('/form', csrfProtection, function (req, res) {
  // pass the csrfToken to the view
  res.render('send', { csrfToken: req.csrfToken() })
})
 
app.post('/process', parseForm, csrfProtection, function (req, res) {
  res.send('data is being processed')
})

// Frontend

<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">
  
  Favorite color: <input type="text" name="favoriteColor">
  <button type="submit">Submit</button>
</form>
```

[CSURF npmjs.com](https://www.npmjs.com/package/csurf)

### Rate limit

```bash
  npm install express-rate-limit
```

Example

```javascript
import rateLimit from 'express-rate-limit'

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})

// Apply the rate limiting middleware to all requests
app.use(limiter)
```

[Express rate limit npmjs.com](https://www.npmjs.com/package/helmet)

### Reduce fingerprinting

Example

```javascript
const express = require('express')
const app = express()

app.disable('x-powered-by')
```

### cors

```bash
  npm install cors
```

Example

```javascript
var express = require('express')
var cors = require('cors')
var app = express()
 
app.use(cors())
 
app.get('/products/:id', function (req, res, next) {
  res.json({msg: 'This is CORS-enabled for all origins!'})
})
 
app.listen(80, function () {
  console.log('CORS-enabled web server listening on port 80')
})
```

[cors npmjs.com](https://www.npmjs.com/package/cors)
