package com.odenizturker.authorizationserver.entity

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.UUID

@Table("users")
class UserEntity(
    @Id
    private val id: UUID? = null,
    private val firstName: String,
    private val secondName: String,
    private val username: String,
    private val emailAddress: String,
    private val password: String,
    private val registrationCompleted: Boolean = false,
    private val expired: Boolean = false,
    private val locked: Boolean = false,
    private val credentialsExpired: Boolean = false,
    private val enabled: Boolean = true,
) : UserDetails {
    override fun getAuthorities(): Set<GrantedAuthority> = setOf()

    override fun getPassword(): String = password

    override fun getUsername(): String = id.toString()

    override fun isAccountNonExpired(): Boolean = !expired

    override fun isAccountNonLocked(): Boolean = !locked

    override fun isCredentialsNonExpired(): Boolean = !credentialsExpired

    override fun isEnabled(): Boolean = enabled
}
