#!/bin/bash
# 读取config.json中的配置
config_file="config.json"
LOG_LEVEL=$(jq -r '.logging_level' "$config_file")
LISTEN_ADDRESS=$(jq -r '.listen_address' "$config_file")
LISTEN_PORT=$(jq -r '.listen_port' "$config_file")
WORKERS=$(jq -r '.workers' "$config_file")

# 将日志级别转换为大写
LOG_LEVEL=${LOG_LEVEL^^}

# 启动Gunicorn，使用从config.json中获取的配置
/usr/bin/env gunicorn \
  -w "$WORKERS" \
  -b "$LISTEN_ADDRESS":"$LISTEN_PORT" \
  --log-level "$LOG_LEVEL" \
  app:APP
