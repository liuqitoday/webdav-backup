#!/usr/bin/env python3
"""
WebDAV备份脚本
支持文件和目录的定期备份到WebDAV服务器
"""

import os
import sys
import yaml
import shutil
import logging
import tempfile
import datetime
import zipfile
import tarfile
import traceback
import requests
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/webdav_backup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class WebDAVBackup:
    def __init__(self, config_path: str = "config.yaml"):
        """初始化备份工具"""
        self.config_path = config_path
        self.config = self.load_config()
        
        # 初始化requests会话
        self.session = self.init_requests_session()
        
        # 测试连接
        self.test_connection()
        
        # 初始化WebDAV客户端（可选，使用webdav3库）
        self.webdav_client = None
        try:
            from webdav3.client import Client
            self.webdav_client = self.init_webdav_client()
        except ImportError:
            logger.warning("webdav3库未安装，将使用基本HTTP请求")
        
        # 确保临时目录存在
        self.temp_dir = Path(self.config['backup']['temp_dir'])
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # 验证必要配置
            required_keys = ['webdav', 'backup']
            for key in required_keys:
                if key not in config:
                    raise ValueError(f"缺少必要的配置项: {key}")
            
            # 验证子配置项
            webdav_required = ['url', 'username', 'password']
            for key in webdav_required:
                if key not in config['webdav']:
                    raise ValueError(f"webdav配置缺少: {key}")
            
            # 设置默认值
            config['webdav'].setdefault('timeout', 30)
            
            backup_config = config['backup']
            backup_config.setdefault('sources', [])
            backup_config.setdefault('target_dir', '/backups/')
            backup_config.setdefault('keep_versions', 6)
            backup_config.setdefault('timestamp_format', '%Y%m%d_%H%M%S')
            backup_config.setdefault('temp_dir', '/tmp/webdav_backup')
            backup_config.setdefault('compression', 'tar.gz')
            backup_config.setdefault('include_hidden', False)
            
            # 处理目标目录格式
            if not backup_config['target_dir'].startswith('/'):
                backup_config['target_dir'] = '/' + backup_config['target_dir']
            
            return config
        except FileNotFoundError:
            logger.error(f"配置文件不存在: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"配置文件解析错误: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"加载配置时发生错误: {e}")
            logger.error(traceback.format_exc())
            sys.exit(1)
    
    def init_requests_session(self) -> requests.Session:
        """初始化requests会话用于手动WebDAV操作"""
        webdav_config = self.config['webdav']
        
        session = requests.Session()
        
        # 添加基础认证
        auth_str = f"{webdav_config['username']}:{webdav_config['password']}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        session.headers.update({
            'Authorization': f'Basic {auth_b64}',
            'User-Agent': 'WebDAV-Backup/1.0'
        })
        
        session.timeout = webdav_config['timeout']
        
        return session
    
    def test_connection(self):
        """测试WebDAV连接"""
        webdav_config = self.config['webdav']
        url = webdav_config['url'].rstrip('/') + '/'
        
        logger.info(f"WebDAV URL: {url}")
        logger.info(f"WebDAV 用户名: {webdav_config['username']}")
        logger.info("正在测试WebDAV连接...")
        
        try:
            # 尝试OPTIONS请求
            response = self.session.request('OPTIONS', url, timeout=10)
            logger.info(f"服务器支持的方法: {response.headers.get('Allow', '未知')}")
            
            # 尝试访问根目录
            response = self.session.request('PROPFIND', url, depth='0', timeout=10)
            
            if response.status_code in [200, 207]:
                logger.info(f"✓ WebDAV连接认证成功 (状态码: {response.status_code})")
            elif response.status_code == 401:
                logger.error(f"✗ 认证失败 (401 Unauthorized)")
                logger.error("请检查用户名和密码是否正确")
                logger.error(f"URL: {url}")
                logger.error(f"用户名: {webdav_config['username']}")
                sys.exit(1)
            else:
                logger.warning(f"⚠ 非预期状态码: {response.status_code}")
                logger.warning(f"响应内容: {response.text[:200]}")
                
        except requests.exceptions.ConnectionError:
            logger.error(f"✗ 无法连接到服务器: {url}")
            logger.error("请检查: 1) 服务器地址和端口是否正确 2) 服务器是否运行 3) 防火墙设置")
            sys.exit(1)
        except Exception as e:
            logger.error(f"✗ 连接测试异常: {e}")
            sys.exit(1)
    
    def init_webdav_client(self):
        """初始化WebDAV客户端（可选）"""
        try:
            from webdav3.client import Client
            
            webdav_config = self.config['webdav']
            url = webdav_config['url'].rstrip('/') + '/'
            
            options = {
                'webdav_hostname': url,
                'webdav_login': webdav_config['username'],
                'webdav_password': webdav_config['password'],
                'webdav_timeout': webdav_config['timeout'],
            }
            
            client = Client(options)
            logger.info("WebDAV客户端初始化成功")
            return client
            
        except ImportError:
            logger.warning("webdav3库未安装，将使用基本HTTP请求")
            return None
        except Exception as e:
            logger.warning(f"WebDAV客户端初始化失败: {e}")
            logger.warning("将使用基本HTTP请求")
            return None
    
    def ensure_webdav_directory(self, directory_path: str) -> bool:
        """确保WebDAV目录存在"""
        webdav_config = self.config['webdav']
        base_url = webdav_config['url'].rstrip('/')
        
        # 如果目录路径是根目录
        if directory_path == '/':
            return True
        
        # 移除开头的斜杠
        dir_path = directory_path.strip('/')
        if not dir_path:
            return True
        
        # 分解目录路径
        parts = dir_path.split('/')
        current_path = ""
        
        for i, part in enumerate(parts):
            if not part:
                continue
                
            current_path += part + "/"
            dir_url = base_url + "/" + current_path
            
            logger.debug(f"检查目录: {current_path}")
            
            try:
                # 尝试访问目录
                response = self.session.request('PROPFIND', dir_url, depth='0', timeout=10)
                
                if response.status_code == 404:
                    # 目录不存在，创建它
                    logger.info(f"创建目录: {current_path}")
                    response = self.session.request('MKCOL', dir_url, timeout=10)
                    
                    if response.status_code in [200, 201, 405]:
                        logger.info(f"✓ 目录创建成功: {current_path}")
                    else:
                        logger.error(f"✗ 创建目录失败 {current_path}: {response.status_code}")
                        logger.error(f"响应: {response.text[:200]}")
                        return False
                        
                elif response.status_code in [200, 207, 301, 302]:
                    # 目录已存在
                    logger.debug(f"✓ 目录已存在: {current_path}")
                else:
                    logger.error(f"✗ 检查目录失败 {current_path}: {response.status_code}")
                    logger.error(f"响应: {response.text[:200]}")
                    return False
                    
            except Exception as e:
                logger.error(f"处理目录时出错 {current_path}: {e}")
                return False
        
        logger.info(f"✓ 所有目录已确保存在: {directory_path}")
        return True
    
    def compress_file_or_dir(self, source_path: str) -> Optional[Path]:
        """压缩文件或目录"""
        backup_config = self.config['backup']
        timestamp = datetime.datetime.now().strftime(backup_config['timestamp_format'])
        
        # 获取源路径的基名
        source = Path(source_path)
        if not source.exists():
            logger.warning(f"源路径不存在: {source_path}")
            return None
        
        # 生成备份文件名
        if source.is_file():
            base_name = source.stem
            suffix = source.suffix
            backup_name = f"{base_name}_{timestamp}"
        else:
            backup_name = f"{source.name}_{timestamp}"
        
        # 添加压缩扩展名
        compression = backup_config['compression']
        if compression == "zip":
            backup_file = self.temp_dir / f"{backup_name}.zip"
            self._create_zip(source, backup_file)
        elif compression == "tar.gz":
            backup_file = self.temp_dir / f"{backup_name}.tar.gz"
            self._create_targz(source, backup_file)
        else:
            logger.error(f"不支持的压缩格式: {compression}")
            return None
        
        if backup_file.exists():
            file_size = backup_file.stat().st_size
            if file_size > 1024 * 1024:  # 大于1MB
                size_str = f"{file_size / (1024 * 1024):.2f} MB"
            elif file_size > 1024:  # 大于1KB
                size_str = f"{file_size / 1024:.2f} KB"
            else:
                size_str = f"{file_size} B"
                
            logger.info(f"✓ 已压缩: {source_path} -> {backup_file} ({size_str})")
            return backup_file
        else:
            logger.error(f"压缩文件创建失败: {backup_file}")
            return None
    
    def _create_zip(self, source: Path, dest: Path):
        """创建ZIP压缩文件"""
        include_hidden = self.config['backup']['include_hidden']
        
        try:
            with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if source.is_file():
                    zipf.write(source, source.name)
                else:
                    for item in source.rglob('*'):
                        if not include_hidden and any(part.startswith('.') for part in item.parts):
                            continue
                        
                        # 计算相对路径
                        rel_path = item.relative_to(source)
                        if item.is_file():
                            zipf.write(item, rel_path)
        except Exception as e:
            logger.error(f"创建ZIP文件失败: {e}")
            if dest.exists():
                dest.unlink()
            raise
    
    def _create_targz(self, source: Path, dest: Path):
        """创建tar.gz压缩文件"""
        include_hidden = self.config['backup']['include_hidden']
        
        def filter_func(tarinfo):
            if not include_hidden and '/' in tarinfo.name and any(
                part.startswith('.') for part in tarinfo.name.split('/')
            ):
                return None
            return tarinfo
        
        try:
            with tarfile.open(dest, 'w:gz') as tar:
                if source.is_file():
                    tar.add(source, arcname=source.name, filter=filter_func)
                else:
                    tar.add(source, arcname=source.name, filter=filter_func)
        except Exception as e:
            logger.error(f"创建tar.gz文件失败: {e}")
            if dest.exists():
                dest.unlink()
            raise
    
    def upload_file(self, local_file: Path) -> bool:
        """上传文件到WebDAV"""
        backup_config = self.config['backup']
        target_dir = backup_config['target_dir']
        
        logger.info(f"目标目录: {target_dir}")
        
        # 1. 确保目标目录存在
        if not self.ensure_webdav_directory(target_dir):
            logger.error(f"无法确保目录存在: {target_dir}")
            return False
        
        # 2. 构建远程路径
        webdav_config = self.config['webdav']
        base_url = webdav_config['url'].rstrip('/')
        
        # 处理目标目录格式
        if target_dir == '/':
            remote_path = f"{base_url}/{local_file.name}"
        else:
            remote_path = f"{base_url}{target_dir.rstrip('/')}/{local_file.name}"
        
        logger.info(f"上传文件到: {remote_path}")
        
        # 3. 读取文件内容
        try:
            with open(local_file, 'rb') as f:
                file_content = f.read()
        except Exception as e:
            logger.error(f"读取本地文件失败: {e}")
            return False
        
        # 4. 上传文件
        try:
            response = self.session.put(
                remote_path,
                data=file_content,
                timeout=webdav_config['timeout']
            )
            
            if response.status_code in [200, 201, 204]:
                logger.info(f"✓ 文件上传成功: {local_file.name}")
                return True
            else:
                logger.error(f"✗ 文件上传失败: {response.status_code}")
                logger.error(f"响应: {response.text[:200]}")
                return False
                
        except Exception as e:
            logger.error(f"上传文件异常: {e}")
            return False
    
    def list_backup_files(self) -> List[str]:
        """列出备份目录中的所有文件"""
        backup_config = self.config['backup']
        target_dir = backup_config['target_dir']
        webdav_config = self.config['webdav']
        base_url = webdav_config['url'].rstrip('/')
        
        # 构建目录URL
        if target_dir == '/':
            dir_url = base_url + '/'
        else:
            dir_url = base_url + target_dir.rstrip('/') + '/'
        
        try:
            response = self.session.request('PROPFIND', dir_url, timeout=10)
            
            if response.status_code not in [200, 207]:
                logger.error(f"列出文件失败: {response.status_code}")
                logger.error(f"响应: {response.text[:200]}")
                return []
            
            # 简单的文件列表提取（基于常见的WebDAV响应格式）
            files = []
            
            # 方法1: 尝试从href中提取
            content = response.text
            lines = content.split('\n')
            
            for line in lines:
                if 'href>' in line:
                    # 提取href内容
                    start = line.find('>') + 1
                    end = line.find('<', start)
                    if start > 0 and end > start:
                        href = line[start:end]
                        # 移除URL前缀
                        if href.startswith(dir_url):
                            filename = href[len(dir_url):]
                            if filename and filename != dir_url and not filename.endswith('/'):
                                files.append(filename)
            
            # 方法2: 如果上面没找到，尝试简单解析
            if not files and '<D:href>' in content:
                import re
                # 简单的正则匹配
                pattern = r'<D:href>(.*?)</D:href>'
                matches = re.findall(pattern, content)
                for match in matches:
                    if match.startswith(dir_url):
                        filename = match[len(dir_url):]
                        if filename and filename != dir_url and not filename.endswith('/'):
                            files.append(filename)
            
            # 去重和过滤
            files = list(set(files))
            files = [f for f in files if f]  # 移除空字符串
            
            logger.info(f"找到 {len(files)} 个备份文件")
            return files
            
        except Exception as e:
            logger.error(f"列出文件时出错: {e}")
            return []
    
    def cleanup_old_backups(self):
        """清理旧的备份文件"""
        backup_config = self.config['backup']
        keep_versions = backup_config['keep_versions']
        
        try:
            # 获取备份文件列表
            backup_files = self.list_backup_files()
            
            if not backup_files:
                logger.info("备份目录为空，无需清理")
                return
            
            # 如果文件数量超过保留数量，删除最旧的
            if len(backup_files) > keep_versions:
                # 按文件名排序（假设包含时间戳）
                backup_files.sort()
                
                # 删除最旧的文件
                files_to_delete = backup_files[:-keep_versions]
                logger.info(f"需要删除 {len(files_to_delete)} 个旧备份")
                
                deleted_count = 0
                for filename in files_to_delete:
                    if self.delete_remote_file(filename):
                        deleted_count += 1
                        logger.info(f"✓ 已删除旧备份: {filename}")
                    else:
                        logger.error(f"✗ 删除备份失败: {filename}")
                
                logger.info(f"清理完成，删除了 {deleted_count} 个旧备份")
            else:
                logger.info(f"备份数量 ({len(backup_files)}) 未超过保留限制 ({keep_versions})")
                        
        except Exception as e:
            logger.error(f"清理旧备份时出错: {e}")
            logger.error(traceback.format_exc())
    
    def delete_remote_file(self, filename: str) -> bool:
        """删除远程文件"""
        backup_config = self.config['backup']
        target_dir = backup_config['target_dir']
        webdav_config = self.config['webdav']
        base_url = webdav_config['url'].rstrip('/')
        
        # 构建完整URL
        if target_dir == '/':
            file_url = base_url + '/' + filename
        else:
            file_url = base_url + target_dir.rstrip('/') + '/' + filename
        
        try:
            response = self.session.delete(file_url, timeout=10)
            if response.status_code in [200, 204]:
                return True
            else:
                logger.error(f"删除文件失败 {filename}: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"删除文件异常 {filename}: {e}")
            return False
    
    def cleanup_temp_files(self):
        """清理临时文件"""
        try:
            # 删除临时目录中的所有文件
            deleted_count = 0
            for file in self.temp_dir.glob('*'):
                try:
                    if file.is_file():
                        file.unlink()
                        deleted_count += 1
                except Exception as e:
                    logger.warning(f"删除临时文件失败 {file}: {e}")
            
            if deleted_count > 0:
                logger.info(f"已清理 {deleted_count} 个临时文件")
        except Exception as e:
            logger.error(f"清理临时文件时出错: {e}")
    
    def run_backup(self):
        """执行备份流程"""
        backup_config = self.config['backup']
        sources = backup_config['sources']
        
        logger.info("=" * 60)
        logger.info("开始备份流程")
        logger.info(f"备份源数量: {len(sources)}")
        logger.info(f"临时目录: {self.temp_dir}")
        logger.info(f"目标目录: {backup_config['target_dir']}")
        logger.info("=" * 60)
        
        success_count = 0
        failed_count = 0
        
        # 备份每个源
        for i, source in enumerate(sources, 1):
            logger.info(f"[{i}/{len(sources)}] 备份源: {source}")
            
            try:
                # 压缩文件/目录
                compressed_file = self.compress_file_or_dir(source)
                if compressed_file is None:
                    failed_count += 1
                    continue
                
                # 上传到WebDAV
                if self.upload_file(compressed_file):
                    success_count += 1
                else:
                    failed_count += 1
                
                # 删除本地临时文件
                try:
                    compressed_file.unlink()
                    logger.debug(f"已删除临时文件: {compressed_file}")
                except Exception as e:
                    logger.warning(f"删除临时压缩文件失败: {e}")
                    
            except Exception as e:
                logger.error(f"备份失败 {source}: {e}")
                logger.error(traceback.format_exc())
                failed_count += 1
        
        # 清理旧备份
        if success_count > 0:
            logger.info("开始清理旧备份...")
            self.cleanup_old_backups()
        
        # 清理临时文件
        logger.info("开始清理临时文件...")
        self.cleanup_temp_files()
        
        logger.info("=" * 60)
        logger.info(f"备份完成。成功: {success_count}, 失败: {failed_count}")
        
        if failed_count == len(sources):
            logger.error("所有备份都失败了！")
            sys.exit(1)
        elif failed_count > 0:
            logger.warning("部分备份失败")
            sys.exit(0)  # 部分成功也返回成功
        else:
            logger.info("✓ 所有备份都成功了！")
            sys.exit(0)


def main():
    """主函数"""
    # 检查配置文件路径
    config_path = "config.yaml"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    try:
        # 执行备份
        backup = WebDAVBackup(config_path)
        backup.run_backup()
    except Exception as e:
        logger.error(f"备份过程发生未捕获的异常: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
