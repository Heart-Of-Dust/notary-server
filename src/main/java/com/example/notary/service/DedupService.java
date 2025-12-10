package com.example.notary.service;
import com.example.notary.config.Const;
import org.springframework.data.redis.core.*;
import org.springframework.stereotype.*;
import java.time.Duration;

@Component
public class DedupService {
    private final StringRedisTemplate redis;
    public DedupService(StringRedisTemplate redis) { this.redis = redis; }
    public boolean exist(String user, String msgHash, long ts) {
        String key = "dedup:%s:%s:%d".formatted(user, msgHash, ts);
        Boolean b = redis.opsForValue().setIfAbsent(key, "1", Duration.ofSeconds(Const.DEDUP_TTL));
        return Boolean.FALSE.equals(b);
    }
}