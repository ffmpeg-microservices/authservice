package com.mediaalterations.authservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public <T> T get(String key, Class<T> entityClass) {
        try {
            String s = redisTemplate.opsForValue().get(key);
            if (s == null) // key not found
                return null;
            return objectMapper.readValue(s, entityClass);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public void set(String key, Object o, Long ttl) {
        String convertedValue = objectMapper.writeValueAsString(o);
        redisTemplate.opsForValue().set(key, convertedValue, ttl, TimeUnit.HOURS);
    }

    public String delete(String key) {
        return redisTemplate.opsForValue().getAndDelete(key);
    }

}
