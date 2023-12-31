# Project Functions

## General Project Enhancements

### 1. User Profile & Avatar

### 2. Logging & Error Handling

### 3. Resilience

### 4. Nginx Setup

### 5. User Account Management


### 6. Code Cleanup

### 7. Frontend

### 8. QA

## Additional Security Measures

### 1. Firewall

## Future Implementations

### 1. Anti-Virus (AV)

### 2. Database Permissions

### 3. Web Server Account

### 4. Make use of Google Authentication on root account 


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


# Vuln App Features

1. **HTML Injection**: Vulnerable to HTML Injection, allowing an attacker to inject malicious code into web pages.

2. **XSS (Cross-Site Scripting)**: Susceptible to Cross-Site Scripting attacks, where untrusted input can be executed as code in a user's browser.

3. **SSTI (Server-Side Template Injection)**: Prone to Server-Side Template Injection, enabling attackers to manipulate server-side templates.

4. **SQL Injection**: Vulnerable to SQL Injection, which allows attackers to execute arbitrary SQL queries on the database.

5. **Information Disclosure**: Leaks sensitive information or error messages that could aid attackers.

6. **Command Injection**: Exposes vulnerabilities to Command Injection, enabling malicious execution of arbitrary commands.

7. **Brute Force**: Lacks protection against Brute Force attacks on user accounts and authentication mechanisms.

8. **Deserialization**: Vulnerable to Deserialization attacks, which can lead to remote code execution.

9. **Broken Authentication**: Suffers from Broken Authentication, making it easier for attackers to compromise user accounts.

10. **DoS (Denial of Service)**: Susceptible to Denial of Service attacks, impacting service availability.

11. **File Upload**: Allows file uploads without proper validation, posing a risk for malicious file uploads and potential attacks.
