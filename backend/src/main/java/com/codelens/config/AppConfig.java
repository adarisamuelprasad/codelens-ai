package com.codelens.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    // Reviews are I/O-bound (GitHub API, LLM) and PMD is CPU-light at PR size.
    // Two at a time keeps a small instance responsive; a burst of pushes
    // queues instead of failing.
    @Bean
    public TaskExecutor reviewExecutor() {
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(2);
        ex.setMaxPoolSize(2);
        ex.setQueueCapacity(100);
        ex.setThreadNamePrefix("review-");
        ex.initialize();
        return ex;
    }
}
