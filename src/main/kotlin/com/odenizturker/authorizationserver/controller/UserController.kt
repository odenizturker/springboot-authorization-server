package com.odenizturker.authorizationserver.controller

import com.odenizturker.authorizationserver.entity.UserEntity
import com.odenizturker.authorizationserver.model.RegisterRequest
import com.odenizturker.authorizationserver.service.UserService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
@RequestMapping("/users")
class UserController(
    private val userService: UserService,
) {
    @PostMapping("/register")
    fun register(
        @RequestBody registerRequest: RegisterRequest,
    ): UserEntity = userService.register(registerRequest)

    @GetMapping
    fun getUser(principal: Principal): Principal = principal
}
