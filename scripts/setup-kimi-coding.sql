-- SentinelProxy Kimi coding channel configuration
-- Run this against one-api.db:
--   sqlite3 one-api.db < scripts/setup-kimi-coding.sql

-- Remove existing channel if present
DELETE FROM channels WHERE name = 'kimi-coding';

-- Insert Kimi coding channel
INSERT INTO channels (
    type,
    key,
    status,
    name,
    weight,
    created_time,
    base_url,
    models,
    "group",
    used_quota
) VALUES (
    25,
    'sk-kimi-KFTvvNCl7DgjabdEuxkEKAZNyeWAtUd6hhBuPyF0rLjpwqv7JxN4IyD9IPjDOsCH',
    1,
    'kimi-coding',
    1,
    strftime('%s', 'now'),
    'https://api.kimi.com/coding/',
    '["kimi-for-coding"]',
    'default',
    0
);
