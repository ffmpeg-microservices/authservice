package com.mediaalterations.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RedisSessionDetails {
    private String sessionId;
    private String ipAddress;
}
