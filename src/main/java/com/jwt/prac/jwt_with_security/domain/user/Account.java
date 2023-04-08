package com.jwt.prac.jwt_with_security.domain.user;

import com.jwt.prac.jwt_with_security.domain.constant.Gender;
import com.jwt.prac.jwt_with_security.domain.constant.Role;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.util.Assert;

import javax.persistence.*;

@Entity
@Table(name = "account")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Account {

    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = false, unique = true)
    private String nickName;
    @Column(nullable = false)
    private String password;
    @Column(nullable = false)
    private String name;
    @Column
    private int age;
    @Column // UNKNOWN -> OAuth2 서버측에서 성별 값을 전달받지 못했을 경우
    private Gender gender;
    @Column
    @Enumerated(EnumType.STRING)
    private Role role;
    @Column(length = 100)
    @Lob
    private String refreshToken;

    @Builder
    public Account(String email, String nickName, String password,
                String name, Integer age, Gender gender, Role role) {

        Assert.hasText(email, "email must not be blank");
        Assert.hasText(nickName, "nickName must not be blank");
        Assert.hasText(password, "password must not be blank");
        Assert.hasText(name, "name must not be blank");
        Assert.notNull(age, "age must not be null");

        this.email = email;
        this.nickName = nickName;
        this.password = password;
        this.name = name;
        this.age = age;
        this.gender = gender;
        this.role = role;
    }
}
