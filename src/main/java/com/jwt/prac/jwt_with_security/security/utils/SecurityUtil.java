package com.jwt.prac.jwt_with_security.security.utils;

import com.jwt.prac.jwt_with_security.security.userDetails.AccountContext;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtil {

    public String getLoginUserEmail() {
        AccountContext accountContext = getPrincipalInAuthentication();
        return accountContext.getUsername();
    }

    public Long getLoginUserId() {
        AccountContext accountContext = getPrincipalInAuthentication();
        return accountContext.getAccount().getId();
    }

    public String getLoginUserNickname() {
        AccountContext accountContext = getPrincipalInAuthentication();
        return accountContext.getAccount().getNickName();
    }

    private AccountContext getPrincipalInAuthentication() {
        return (AccountContext) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
