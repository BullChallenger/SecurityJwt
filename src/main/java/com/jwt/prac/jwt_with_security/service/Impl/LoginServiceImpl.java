package com.jwt.prac.jwt_with_security.service.Impl;

import com.jwt.prac.jwt_with_security.domain.user.Account;
import com.jwt.prac.jwt_with_security.domain.user.AccountRepository;
import com.jwt.prac.jwt_with_security.security.userDetails.AccountContext;
import com.jwt.prac.jwt_with_security.service.LoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import javax.persistence.EntityNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByEmail(username).orElseThrow(
                () -> new EntityNotFoundException("Account that use this email can't find")
        );

        String role = account.getRole().name();

        List<GrantedAuthority> authorities = new ArrayList<>();
        Assert.isTrue(!role.startsWith("ROLE_"),
                () -> role + " cannot start with ROLE_ (it is automatically added)");
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));

        return new AccountContext(account.getEmail(), account.getPassword(), (Set<GrantedAuthority>) authorities);
    }
}
