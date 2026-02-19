package com.mediaalterations.authservice.dto;

public record SignupRequest(String username,String password,String fullName, String email) {
}
