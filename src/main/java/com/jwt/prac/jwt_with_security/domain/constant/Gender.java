package com.jwt.prac.jwt_with_security.domain.constant;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Gender {
    MALE("MALE"), FEMALE("FEMALE");

    private String genderValue;

    Gender(String genderValue) {
        this.genderValue = genderValue;
    }

    @JsonValue
    public String getGenderValue() { return this.genderValue; }

    @JsonCreator
    public Gender from(String genderValue) {
        for (Gender status : Gender.values()) {
            if (status.getGenderValue().equals(genderValue)) {
                return status;
            }
        }

        throw new IllegalArgumentException("유효하지 않은 성별입니다.");
    }
}
