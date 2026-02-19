package com.mediaalterations.authservice.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserDto(
    UUID uuid,
    String email,
    String fullname,
    LocalDateTime created_at
) { }