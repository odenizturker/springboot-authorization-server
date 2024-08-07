package com.odenizturker.authorizationserver.controller

import org.springframework.security.core.userdetails.User
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController {
    @GetMapping
    fun getAllUsers(): List<User> {
        return listOf(User.withUsername("demo").build() as User)
    }
}