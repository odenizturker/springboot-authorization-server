package com.odenizturker.authorizationserver.entity

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import org.springframework.security.core.GrantedAuthority
import java.util.UUID

@Table("authorities")
class AuthorityEntity(
    @Id
    private val id: UUID,
    private val authority: String,
) : GrantedAuthority {
    override fun getAuthority(): String = authority
}
