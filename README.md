# WebDAV 备份工具

一个轻量级的 Python 脚本，用于定时备份文件和目录到 WebDAV 服务器。

## 主要功能

- 自动备份文件和目录到 WebDAV
- 支持 ZIP 和 TAR.GZ 压缩格式
- 自动添加时间戳，避免文件覆盖
- 保留最近6个版本，自动清理旧备份
- 详细的日志记录

## 快速开始

### 1. 安装依赖
```bash
pip install PyYAML requests
```

### 2. 配置
配置文件修改：
```bash
nano config.yaml
```

配置文件示例：
```yaml
webdav:
  url: "http://192.168.1.100:8080/"
  username: "your_username"
  password: "your_password"

backup:
  sources:
    - "/etc/nginx"
    - "/var/www/html"
  target_dir: "/backups/"
  keep_versions: 6
```

### 3. 测试运行
```bash
python webdav_backup.py
```

### 4. 设置定时任务
```bash
crontab -e
```
添加（每天凌晨2点备份）：
```
0 2 * * * /usr/bin/python3 /path/to/webdav_backup.py
```

## 文件说明

- `webdav_backup.py` - 主备份脚本
- `config.yaml` - 配置文件
- `requirements.txt` - Python依赖包

## 查看日志
```bash
tail -f /var/log/webdav_backup.log
```

## 注意事项

1. 确保 WebDAV 服务器可访问
2. 配置文件包含密码，请妥善保管
3. 首次使用前先测试连接

## 故障排查

如果备份失败：
1. 检查 WebDAV 连接信息
2. 查看详细日志

## 许可证

MIT License
