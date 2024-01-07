# Spring Security REST API Boilerplate
___
## Overview

This is a boilerplate Spring Boot project designed to kickstart the development of RESTful APIs with built-in Spring Security for authentication and authorization.

## Features

- **Spring Boot:** Utilize the power of the Spring Boot framework for building robust and scalable applications.
- **Spring Security:** Implement secure authentication and authorization mechanisms to protect your REST API.
- **RESTful API:** Design and develop a clean and efficient RESTful API to handle your application's business logic.
- **Customizable:** Easily extend and customize the project to fit your specific requirements.

## Getting Started

1. Clone the repository: `git clone https://github.com/hakimfauzi23/boilerplate-spring-security.git`
2. Navigate to the project directory `cd boilerplate-spring-security`
3. Configure `src/main/resources/application.properties`
    ```properties
   spring.datasource.url= jdbc:mysql://localhost:3306/testdb?useSSL=false
   spring.datasource.username= root
   spring.datasource.password=
   spring.jpa.hibernate.ddl-auto= update
   
   # App Properties
   spring.app.jwtSecret= ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
   spring.app.jwtExpirationMs= 60000
   spring.app.jwtRefreshExpirationMs= 259200000
   ```
4. Create a new database that has a same name in `spring.datasource.url` properties
5. Build the application JAR File : `mvn clean package`
6. Run the application by running the JAR File : `java -jar target/boilerplate-spring-security-0.0.1-SNAPSHOT.jar`
7. Application is running, now you can experiment on the Authentication & Authorization in this project!

## Authentication Feature
The Authentication feature involves generating a JSON Web Token (JWT) for inclusion in the header of each API request. The feature encompasses three distinct endpoints: `api/auth/signup`, `api/auth/signin`, and `api/auth/refresh-token`. Below is a breakdown of each API endpoint:
___
### Sign Up Endpoint
This is for create new user credentials so the authentication login can be done with the user credential.

**API Endpoint:** `http://localhost:8080/api/auth/signup`

**Request:**
```json
{
    "username":"user1",
    "email":"user1@mail.com",
    "password":"12345678",
    "role": ["user"]
}
```

**Response:**
```json
{
   "message": "User registered successfully!"
}
```
___
### Sign In Endpoint
This process involves generating an Access Token (JWT) by sending a request to the sign-in endpoint with the user credentials previously created through the sign-up endpoint.

**API Endpoint:** `http://localhost:8080/api/auth/signin`

**Request**
```json
{
    "username" : "user1",
    "password" : "12345678"
}
```

**Response**
```json
{
    "refreshToken": "80b5f84f-c812-4efb-90a8-94893ec460a9",
    "id": 2,
    "username": "user1",
    "email": "user1@mail.com",
    "roles": [
        "ROLE_USER"
    ],
    "tokenType": "Bearer",
    "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi........"
}
```
### Refresh Token Endpoint
The access token comes with an expiration time. In situations where the access token has expired, but the refresh token is still valid, the refresh token can be employed to generate a new access token.

**API Endpoint:** `http://localhost:8080/api/auth/signin`


**Request**
```json
{
    "refreshToken" : "6c276542-4fdf-4d7c-ba2d-dbd42cc3cfe9"
}
```

**Response**
```json
{
    "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIs............",
    "refreshToken": "80b5f84f-c812-4efb-90a8-94893ec460a9",
    "tokenType": "Bearer"
}
```

___
## Authorization Feature
After gaining an understanding of Authentication and learning how to generate the Access Token, the next step is to comprehend the Authorization feature. This feature is employed to filter the JWT Token based on whether it possesses a role that grants access to a specific endpoint. If the Authorization feature determines that the token lacks the requisite role, access will be denied.

Here's how to make the endpoint have the authorization, please use `@PreAuthorize("hasRole('__ROLE NAME__')")` annotation like below: 
```java
@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}
```

This is how to use Access Token that generated in Authentication Feature, you can use the JWT token in the header `Authorization` with starts of `Bearer` then your Access Token.

```shell
curl -X GET http://localhost:8080/api/test/user \
     -H "Authorization: Bearer __ACCESS TOKEN__" \
     -H "Other-Header: Header-Value"
```