package com.odenizturker.authorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories

@EnableJdbcRepositories
@SpringBootApplication
class SpringBootAuthorizationServerApplication

fun main(args: Array<String>) {
    runApplication<SpringBootAuthorizationServerApplication>(*args)
}
