package com.jwt.prac.jwt_with_security.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.prac.jwt_with_security.domain.user.Account;
import com.jwt.prac.jwt_with_security.dto.AccountDto;
import com.jwt.prac.jwt_with_security.security.token.JsonAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JsonEmailPasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String LOGIN_URI = "/login";
    private static final String AJAX_CHECK_REQUEST_HEADER_VALUE = "XMLHttpRequest";
    private static final String AJAX_CHECK_VALUE = "X-Requested-With";
    private static final String HTTP_METHOD = "POST";
    private static final String CONTENT_TYPE = "application/json";


    private ObjectMapper objectMapper = new ObjectMapper();

    public JsonEmailPasswordAuthenticationFilter() {
        super(new AntPathRequestMatcher(LOGIN_URI, HTTP_METHOD));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (!isAjax(request)) {
            throw new IllegalArgumentException("Authentication is not supported");
        } else if (!request.getContentType().equals(CONTENT_TYPE)) {
            throw new AuthenticationServiceException("This Content-Type is not supported : " + request.getContentType());
        }

        AccountDto accountDto =  objectMapper.readValue(request.getReader(), AccountDto.class);
        if (!StringUtils.hasText(accountDto.getUsername()) || !StringUtils.hasText(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is Empty");
        }

        JsonAuthenticationToken jsonAuthenticationToken = new JsonAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        return getAuthenticationManager().authenticate(jsonAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) {
        if (AJAX_CHECK_REQUEST_HEADER_VALUE.equals(request.getHeader(AJAX_CHECK_VALUE))) {
            return true;
        }

        return false;
    }
}
