<div align="center">

<img src="https://github.com/nxtrace/NTrace-core/raw/main/assets/logo.png" height="200px" alt="NextTrace Logo"/>

</div>

# POW SERVER

NEXTTRACE项目派生的仓库，用于实现POW反爬

server : https://github.com/tsosunchia/powserver

client : https://github.com/tsosunchia/powclient

## 部署（venv）

### 前置依赖

- Python 3
- jq（`launch.sh` 读取 `config.json` 依赖）

### 安装步骤

```bash
git clone https://github.com/tsosunchia/powserver.git
cd powserver
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config_example.json config.json
# 按需修改 config.json
```

### 启动（前台）

```bash
bash launch.sh
```

### systemd 服务（venv）

1. 编辑 `powServer.service`，修改 `User`、`WorkingDirectory`，并确认 `Environment` 中的路径与实际目录一致。
2. 安装并启用服务：

```bash
sudo cp powServer.service /etc/systemd/system/powServer.service
sudo systemctl daemon-reload
sudo systemctl enable --now powServer
```
