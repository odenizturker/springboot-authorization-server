package com.odenizturker.authorizationserver.service

import com.odenizturker.authorizationserver.entity.UserEntity
import com.odenizturker.authorizationserver.model.RegisterRequest
import com.odenizturker.authorizationserver.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
) : UserDetailsService {
    override fun loadUserByUsername(username: String?): UserDetails =
        userRepository.findByUsername(username!!) ?: throw Exception("user not found")

    fun register(registerRequest: RegisterRequest): UserEntity = userRepository.save(registerRequest.toEntity(passwordEncoder))
}
