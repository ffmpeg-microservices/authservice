package com.mediaalterations.authservice.dto;


public record LoginResponse(String jwt, String user_id) { }
