package com.odenizturker.authorizationserver.model

import com.odenizturker.authorizationserver.entity.UserEntity
import org.springframework.security.crypto.password.PasswordEncoder

data class RegisterRequest(
    val firstName: String,
    val secondName: String,
    val username: String,
    val emailAddress: String,
    val password: String,
) {
    fun toEntity(passwordEncoder: PasswordEncoder): UserEntity =
        UserEntity(
            firstName = firstName,
            secondName = secondName,
            username = username,
            emailAddress = emailAddress,
            password = passwordEncoder.encode(password),
        )
}
