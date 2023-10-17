# Project Todo List

## General Project Enhancements

### 1. User Profile & Avatar
- Make the user profile implemented by Albert better / Emil

### 2. Logging & Error Handling
- Implement logging, including Elasticsearch for log management. / Albert

### 3. Resilience
- Enhance database resilience to ensure data integrity and availability. - WIP / Albert

### 4. Nginx Setup
- Configure Nginx for web server with HTTPS support. / Albert

### 5. User Account Management
- Implement user account features such as forgot password, change password, and account deletion. / Valeria or Emil
- Enhance the user experience. / Valeria

### 6. Code Cleanup
- Optimize and clean up the codebase for maintainability. / Will never happen

### 7. Frontend
- Do stuff / Valeria

### 8. QA
-   Pretend you're an idiot using the site and find bugs / Valeria & Emil

### 9. Pentesting
-   Try to breach the website. / Albert

## Additional Security Measures

### 1. Firewall
- Set up a firewall to protect against network threats. / Albert

## Future Implementations

### 1. Anti-Virus (AV)
- Explore integration with AV solutions like pyclamd/clamav for file scanning. / Albert

### 2. Database Permissions
- Enhance database security by restricting permissions (e.g., chmod 600). / Albert

### 3. Web Server Account
- Create a restricted account for the web server to limit potential risks. / Albert

### 4. Make use of Google Authentication on root account 
- Use Google authentication to validate privilege esaclation 


# Security Messures Implemented 
1. **CSRF Protection (Flask-WTF) - WIP**: Protects against Cross-Site Request Forgery (CSRF) attacks by generating and verifying tokens for each form submission.

2. **Rate Limiting with Flask Limiter**: Limits the number of requests a client can make in a given timeframe, guarding against abuse and denial-of-service attacks.

3. **Password Hashing with Bcrypt**: Securely hashes user passwords before storage to protect user credentials from exposure in the event of a data breach.

4. **Session Management**: Manages user sessions securely to handle user authentication and authorization.

5. **Content Security Policy (CSP) with Flask-Talisman**: Implements CSP to prevent Cross-Site Scripting (XSS) attacks by specifying allowed content sources.

6. **SQLAlchemy and Database Constraints**: Uses SQLAlchemy and defines constraints (e.g., unique usernames) to prevent data integrity issues and protect the database.

7. **File Upload Validation**: Validates file uploads by checking file extensions and enforcing a size limit to prevent malicious file uploads and DoS attacks.

8. **Session Timeout**: Sets a session lifetime, logging users out after 30 minutes to enhance security by limiting session exposure.

9. **Session Authentication**: Authenticates user sessions by verifying session data to ensure the user is logged in.

10. **Route Authorization with `admin_required`**: Implements route-level authorization, requiring the 'admin' role to access the admin panel.

11. **Database Query Sanitization**: Protects against SQL injection attacks by escaping and quoting parameters in database queries using SQLAlchemy's query builder.

12. **Error Handling**: Implements error handling for common errors such as 404 and 500, enhancing the user experience and avoiding sensitive information exposure.
