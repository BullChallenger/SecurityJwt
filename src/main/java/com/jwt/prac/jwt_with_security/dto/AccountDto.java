package com.jwt.prac.jwt_with_security.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class AccountDto {

    private final String username;
    private final String password;
}
