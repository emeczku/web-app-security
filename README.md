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
***
## Frontend
As a frontend web developer, there are several important aspects of web security that you should be aware of to ensure that your web applications are secure. Some of the most important aspects of web security for frontend development include:

1. **Input validation**: Always validate and sanitize any data that is received from users or external sources, such as form submissions or API responses. This helps prevent attacks such as SQL injection.

```javascript
// Example of vulnerable code
const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

// Example of input validation to prevent SQL injection
const query = `SELECT * FROM users WHERE username=? AND password=?`;
const params = [username, password];
db.query(query, params, (err, results) => {
  if (err) {
    // Handle error
  } else {
    // Process results
  }
});
```
***
2. **Cross-Site Scripting (XSS)** prevention: XSS attacks occur when malicious scripts are injected into web pages and executed in the browsers of unsuspecting users. Implement proper input validation, output encoding, and use of secure coding practices to prevent XSS attacks.

```javascript
// Example of vulnerable code
const input = `<script>alert('XSS attack!');</script>`;
document.getElementById('output').innerHTML = input;

// Example of input validation to prevent XSS attacks
const input = `<script>alert('XSS attack!');</script>`;
const sanitizedInput = sanitizeHTML(input);
document.getElementById('output').innerHTML = sanitizedInput;

```
***
3. **Cross-Site Request Forgery (CSRF)** protection: CSRF attacks occur when a malicious website tricks a user's browser into making unauthorized requests to another website on which the user is authenticated. Implementing CSRF protection measures, such as using anti-CSRF tokens, can help prevent these attacks.

```javascript
// Example of setting CSRF token in a cookie
function setCSRFTokenInCookie() {
  const csrfToken = generateCSRFToken(); // Generate CSRF token
  document.cookie = `csrfToken=${csrfToken}; Secure; HttpOnly`; // Set CSRF token in a secure, HttpOnly cookie
}

// Example of sending CSRF token in a header with Fetch request
function sendFetchRequest() {
  const csrfToken = getCSRFTokenFromCookie(); // Get CSRF token from cookie

  // Make a POST request with Fetch
  fetch('/api/some_endpoint', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken // Set CSRF token as a custom header
    },
    body: JSON.stringify({ /* request body */ })
  })
    .then(response => {
      // Handle response
    })
    .catch(error => {
      // Handle error
    });
}

```

4. **Content Security Policy (CSP)**: Implementing CSP headers can help mitigate cross-site scripting (XSS) and other code injection attacks by specifying which sources of content are allowed to be loaded by a web page.

```html
<!DOCTYPE html>
<html>
<head>
  <!-- Set Content Security Policy (CSP) headers using meta tags -->
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://example.com;">

  <!-- Other meta tags and head elements -->
  <meta charset="UTF-8">
  <title>My CSP-enabled Web Page</title>
  <!-- ... -->
</head>
<body>
  <!-- HTML body content -->
  <!-- ... -->
</body>
</html>

```
  In this example, the Content-Security-Policy meta tag is used to define the Content Security Policy headers for the page. The default-src, script-src, style-src, and img-src directives are used to specify the allowed sources for various types of resources, such as scripts, styles, and images. In this example, only resources from the same origin ('self') and from https://example.com are allowed, and inline scripts and styles ('unsafe-inline') are also allowed for demonstration purposes. However, it's generally not recommended to use 'unsafe-inline' as it can introduce security risks such as cross-site scripting (XSS) attacks.
  ***

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
