#!/usr/bin/env python3
"""
WebDAV备份脚本
支持文件和目录的定期备份到WebDAV服务器
使用requests直接实现WebDAV操作，避免依赖问题
"""

import os
import sys
import yaml
import shutil
import logging
import datetime
import zipfile
import tarfile
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import requests
from requests.auth import HTTPBasicAuth

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


class WebDAVClient:
    """简单的WebDAV客户端实现"""
    
    def __init__(self, url: str, username: str, password: str, timeout: int = 30):
        self.base_url = url.rstrip('/') + '/'
        self.auth = HTTPBasicAuth(username, password)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({
            'User-Agent': 'WebDAV-Backup/1.0'
        })
    
    def check_connection(self) -> bool:
        """检查WebDAV连接"""
        try:
            response = self.session.request(
                'OPTIONS',
                self.base_url,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # 检查是否支持WebDAV
            dav_header = response.headers.get('DAV', '')
            if '1' in dav_header or '2' in dav_header:
                logger.info(f"WebDAV连接成功，支持的方法: {response.headers.get('Allow', 'Unknown')}")
                return True
            else:
                logger.warning("服务器可能不支持WebDAV协议")
                # 即使不是标准WebDAV也继续尝试
                return True
                
        except requests.exceptions.RequestException as e:
            logger.error(f"WebDAV连接失败: {e}")
            return False
    
    def mkdir(self, remote_path: str) -> bool:
        """创建远程目录"""
        try:
            # 确保路径以/结尾
            if not remote_path.endswith('/'):
                remote_path += '/'
            
            # 逐级创建目录
            parts = remote_path.strip('/').split('/')
            current_path = self.base_url
            
            for i, part in enumerate(parts):
                current_path += part + '/'
                try:
                    response = self.session.request(
                        'MKCOL',
                        current_path,
                        timeout=self.timeout
                    )
                    
                    # 405表示目录已存在，这是正常的
                    if response.status_code == 405:
                        continue
                    response.raise_for_status()
                    
                except requests.exceptions.RequestException as e:
                    # 忽略目录已存在的错误
                    if hasattr(e.response, 'status_code') and e.response.status_code == 405:
                        continue
                    logger.warning(f"创建目录失败 {current_path}: {e}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"创建目录时发生错误: {e}")
            return False
    
    def upload_file(self, remote_path: str, local_path: str) -> bool:
        """上传文件到WebDAV"""
        try:
            # 确保远程路径不以/开头（相对于base_url）
            if remote_path.startswith('/'):
                remote_path = remote_path[1:]
            
            remote_url = self.base_url + remote_path
            
            # 创建父目录
            parent_dir = '/'.join(remote_path.split('/')[:-1])
            if parent_dir:
                self.mkdir(parent_dir)
            
            # 上传文件
            with open(local_path, 'rb') as f:
                response = self.session.put(
                    remote_url,
                    data=f,
                    timeout=self.timeout * 2  # 上传需要更多时间
                )
            
            response.raise_for_status()
            logger.debug(f"文件上传成功: {remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"上传文件失败 {local_path} -> {remote_path}: {e}")
            return False
    
    def list_files(self, remote_path: str = '') -> List[str]:
        """列出远程目录中的文件"""
        try:
            if remote_path and not remote_path.endswith('/'):
                remote_path += '/'
            
            remote_url = self.base_url + remote_path
            
            response = self.session.request(
                'PROPFIND',
                remote_url,
                headers={'Depth': '1'},
                timeout=self.timeout
            )
            
            if response.status_code == 207:  # Multi-Status
                # 简单的XML解析，获取文件名
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)
                
                files = []
                # 寻找所有href元素
                for elem in root.findall('.//{DAV:}href'):
                    path = elem.text.strip()
                    if path:
                        # 移除base_url部分和当前路径部分
                        if path.startswith(self.base_url):
                            path = path[len(self.base_url):]
                        elif path.startswith('/' + remote_path.lstrip('/')):
                            path = path[len('/' + remote_path.lstrip('/')):]
                        
                        # 只返回文件（不以/结尾的）
                        if path and not path.endswith('/'):
                            files.append(path)
                
                return files
            else:
                # 如果PROPFIND失败，尝试备用方法
                logger.warning(f"PROPFIND失败 (状态码: {response.status_code})，使用备用方法")
                return self._list_files_fallback(remote_url)
                    
        except Exception as e:
            logger.error(f"列出文件时出错: {e}")
            return []
    
    def _list_files_fallback(self, remote_url: str) -> List[str]:
        """备用方法列出文件"""
        try:
            response = self.session.get(remote_url, timeout=self.timeout)
            
            if response.status_code == 200:
                # 尝试从HTML中解析文件列表
                import re
                # 简单的正则匹配，适用于大多数WebDAV服务器
                files = []
                
                # 匹配超链接中的文件名
                # 这个正则可能需要根据你的WebDAV服务器调整
                pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
                matches = re.findall(pattern, response.text)
                
                for match in matches:
                    # 移除查询参数和锚点
                    file_path = match.split('?')[0].split('#')[0]
                    
                    # 跳过目录和特殊文件
                    if (file_path and 
                        not file_path.endswith('/') and 
                        file_path != '.' and 
                        file_path != '..' and
                        not file_path.startswith('http://') and
                        not file_path.startswith('https://')):
                        files.append(file_path)
                
                logger.info(f"备用方法找到 {len(files)} 个文件")
                return files
            else:
                logger.warning(f"备用方法也失败: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"备用方法出错: {e}")
            return []
    
    def delete_file(self, remote_path: str) -> bool:
        """删除远程文件"""
        try:
            if remote_path.startswith('/'):
                remote_path = remote_path[1:]
            
            remote_url = self.base_url + remote_path
            
            response = self.session.delete(
                remote_url,
                timeout=self.timeout
            )
            
            # 200, 204, 404（文件不存在）都算成功
            if response.status_code in [200, 204] or response.status_code == 404:
                return True
            else:
                logger.warning(f"删除文件失败 {remote_path}: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"删除文件时出错 {remote_path}: {e}")
            return False


class WebDAVBackup:
    def __init__(self, config_path: str = "config.yaml"):
        """初始化备份工具"""
        self.config_path = config_path
        self.config = self.load_config()
        
        # 初始化WebDAV客户端
        webdav_config = self.config['webdav']
        self.webdav_client = WebDAVClient(
            url=webdav_config['url'],
            username=webdav_config['username'],
            password=webdav_config['password'],
            timeout=webdav_config.get('timeout', 30)
        )
        
        # 测试连接
        if not self.webdav_client.check_connection():
            logger.error("无法连接到WebDAV服务器，请检查配置")
            sys.exit(1)
        
        # 确保临时目录存在
        self.temp_dir = Path(self.config['backup']['temp_dir'])
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化源信息映射
        self.source_names = {}  # 源路径 -> 备份文件基础名称
        
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
            
            return config
        except FileNotFoundError:
            logger.error(f"配置文件不存在: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"配置文件解析错误: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"加载配置时发生错误: {e}")
            sys.exit(1)
    
    def get_source_base_name(self, source_path: str) -> str:
        """根据源路径获取备份文件的基础名称"""
        source = Path(source_path)
        if source.is_file():
            return source.stem  # 文件名（不含扩展名）
        else:
            return source.name  # 目录名
    
    def compress_file_or_dir(self, source_path: str) -> Optional[Path]:
        """压缩文件或目录"""
        backup_config = self.config['backup']
        timestamp = datetime.datetime.now().strftime(backup_config['timestamp_format'])
        
        # 获取源路径
        source = Path(source_path)
        if not source.exists():
            logger.warning(f"源路径不存在: {source_path}")
            return None
        
        # 获取源的基础名称
        base_name = self.get_source_base_name(source_path)
        
        # 记录源信息（用于后续清理）
        self.source_names[base_name] = source_path
        
        # 生成备份文件名
        backup_name = f"{base_name}_{timestamp}"
        
        # 添加压缩扩展名
        compression = backup_config['compression']
        if compression == "zip":
            backup_file = self.temp_dir / f"{backup_name}.zip"
            self._create_zip(source, backup_file)
        elif compression == "tar.gz":
            backup_file = self.temp_dir / f"{backup_name}.tar.gz"
            self._create_targz(source, backup_file)
        else:
            raise ValueError(f"不支持的压缩格式: {compression}")
        
        logger.info(f"已压缩: {source_path} -> {backup_file}")
        return backup_file
    
    def _create_zip(self, source: Path, dest: Path):
        """创建ZIP压缩文件"""
        include_hidden = self.config['backup']['include_hidden']
        
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
                    elif item.is_dir():
                        # 添加空目录
                        zipf.write(item, rel_path)
    
    def _create_targz(self, source: Path, dest: Path):
        """创建tar.gz压缩文件"""
        include_hidden = self.config['backup']['include_hidden']
        
        def filter_func(tarinfo):
            if not include_hidden and '/' in tarinfo.name and any(
                part.startswith('.') for part in tarinfo.name.split('/')
            ):
                return None
            return tarinfo
        
        with tarfile.open(dest, 'w:gz') as tar:
            if source.is_file():
                tar.add(source, arcname=source.name, filter=filter_func)
            else:
                tar.add(source, arcname=source.name, filter=filter_func)
    
    def extract_backup_info(self, filename: str) -> Optional[Tuple[str, str]]:
        """从备份文件名中提取源名称和时间戳"""
        # 支持的压缩格式
        compression_extensions = ['.zip', '.tar.gz']
        
        # 移除压缩扩展名
        base_name = filename
        for ext in compression_extensions:
            if filename.endswith(ext):
                base_name = filename[:-len(ext)]
                break
        else:
            # 不是压缩文件，跳过
            return None
        
        # 匹配模式：基础名称_时间戳
        # 使用正则表达式匹配，更灵活
        pattern = r'^(.*?)_(\d{8}_\d{6})$'  # 匹配 "name_YYYYMMDD_HHMMSS"
        match = re.match(pattern, base_name)
        
        if match:
            source_name = match.group(1)
            timestamp = match.group(2)
            return (source_name, timestamp)
        
        # 尝试其他时间戳格式
        patterns = [
            r'^(.*?)_(\d{14})$',  # 匹配 "name_YYYYMMDDHHMMSS"
            r'^(.*?)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$',  # 匹配 "name_YYYY-MM-DD_HH-MM-SS"
        ]
        
        for pattern in patterns:
            match = re.match(pattern, base_name)
            if match:
                source_name = match.group(1)
                timestamp = match.group(2)
                return (source_name, timestamp)
        
        return None
    
    def group_backups_by_source(self, files: List[str]) -> Dict[str, List[Tuple[str, str, str]]]:
        """按源文件/目录分组备份文件
        
        返回: {source_name: [(timestamp, filename, datetime_obj), ...]}
        """
        source_groups = {}
        
        for filename in files:
            info = self.extract_backup_info(filename)
            if info:
                source_name, timestamp = info
                
                # 将时间戳转换为可比较的datetime对象
                try:
                    # 尝试解析时间戳格式
                    timestamp_formats = [
                        '%Y%m%d_%H%M%S',  # YYYYMMDD_HHMMSS
                        '%Y%m%d%H%M%S',   # YYYYMMDDHHMMSS
                        '%Y-%m-%d_%H-%M-%S',  # YYYY-MM-DD_HH-MM-SS
                    ]
                    
                    dt_obj = None
                    for fmt in timestamp_formats:
                        try:
                            dt_obj = datetime.datetime.strptime(timestamp, fmt)
                            break
                        except ValueError:
                            continue
                    
                    if dt_obj is None:
                        # 无法解析时间戳，跳过
                        logger.warning(f"无法解析时间戳: {timestamp} (文件名: {filename})")
                        continue
                    
                    if source_name not in source_groups:
                        source_groups[source_name] = []
                    
                    source_groups[source_name].append((timestamp, filename, dt_obj))
                    
                except Exception as e:
                    logger.warning(f"处理备份文件 {filename} 时出错: {e}")
                    continue
        
        # 按时间戳排序每个源的备份
        for source_name in source_groups:
            source_groups[source_name].sort(key=lambda x: x[2], reverse=True)  # 最新的在前面
        
        return source_groups
    
    def cleanup_old_backups_for_source(self, source_groups: Dict[str, List[Tuple[str, str, datetime.datetime]]], 
                                      source_path: str, keep_versions: int):
        """清理特定源的旧备份"""
        backup_config = self.config['backup']
        target_dir = backup_config['target_dir'].lstrip('/')
        
        # 获取当前源的基名
        source_name = self.get_source_base_name(source_path)
        
        # 检查是否有这个源的备份
        if source_name not in source_groups:
            logger.info(f"没有找到 {source_name} 的备份文件")
            return
        
        # 获取该源的所有备份文件
        backups = source_groups[source_name]
        
        logger.info(f"找到 {source_name} 的 {len(backups)} 个备份")
        
        # 打印备份列表（调试用）
        for i, (timestamp, filename, dt_obj) in enumerate(backups, 1):
            logger.debug(f"  {i}. {filename} (时间: {timestamp})")
        
        # 如果备份数量超过保留数量，删除最旧的
        if len(backups) > keep_versions:
            # 需要删除的备份（最旧的，在列表最后）
            backups_to_delete = backups[keep_versions:]
            
            for timestamp, filename, dt_obj in backups_to_delete:
                # 构建完整路径
                remote_path = f"{target_dir}/{filename}" if target_dir else filename
                
                if self.webdav_client.delete_file(remote_path):
                    logger.info(f"已删除 {source_name} 的旧备份: {filename} (时间戳: {timestamp})")
                else:
                    logger.warning(f"删除 {source_name} 的备份失败: {filename}")
        else:
            logger.info(f"{source_name} 的备份数量 {len(backups)} 小于等于保留数量 {keep_versions}，无需清理")
    
    def cleanup_old_backups(self):
        """清理旧的备份文件 - 按源分别清理"""
        backup_config = self.config['backup']
        keep_versions = backup_config['keep_versions']
        target_dir = backup_config['target_dir'].lstrip('/')
        
        try:
            # 获取目标目录下的所有文件
            logger.info(f"正在列出目录: {target_dir or '根目录'}")
            files = self.webdav_client.list_files(target_dir)
            
            if not files:
                logger.info(f"目标目录 {target_dir} 中没有文件")
                return
            
            logger.info(f"找到 {len(files)} 个文件")
            for i, file in enumerate(files[:10], 1):  # 只显示前10个文件
                logger.debug(f"  {i}. {file}")
            if len(files) > 10:
                logger.debug(f"  ... 还有 {len(files) - 10} 个文件")
            
            # 按源文件/目录分组备份文件
            source_groups = self.group_backups_by_source(files)
            
            if not source_groups:
                logger.warning("无法识别任何备份文件。可能的原因：")
                logger.warning("1. 备份文件名格式不匹配")
                logger.warning("2. 文件不是备份文件")
                logger.warning("3. 文件名中的时间戳格式不匹配")
                
                # 显示一些示例文件名帮助调试
                if files:
                    logger.warning("示例文件名:")
                    for file in files[:5]:
                        logger.warning(f"  - {file}")
                
                return
            
            logger.info(f"识别到 {len(source_groups)} 个不同的备份源")
            for source_name in source_groups:
                logger.info(f"  - {source_name}: {len(source_groups[source_name])} 个备份")
            
            # 为每个配置的源清理旧备份
            backup_sources = backup_config['sources']
            logger.info(f"配置了 {len(backup_sources)} 个备份源")
            
            for source_path in backup_sources:
                self.cleanup_old_backups_for_source(source_groups, source_path, keep_versions)
                        
        except Exception as e:
            logger.error(f"清理旧备份时出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def cleanup_temp_files(self):
        """清理临时文件"""
        try:
            # 删除临时目录中的所有文件
            for file in self.temp_dir.glob('*'):
                try:
                    if file.is_file():
                        file.unlink()
                        logger.debug(f"已删除临时文件: {file}")
                except Exception as e:
                    logger.warning(f"删除临时文件失败 {file}: {e}")
            
            logger.info("已清理临时文件")
        except Exception as e:
            logger.error(f"清理临时文件时出错: {e}")
    
    def run_backup(self):
        """执行备份流程"""
        backup_config = self.config['backup']
        sources = backup_config['sources']
        
        logger.info("=" * 60)
        logger.info("开始备份流程")
        logger.info(f"备份源数量: {len(sources)}")
        logger.info(f"每个源保留版本数: {backup_config['keep_versions']}")
        logger.info(f"时间戳格式: {backup_config['timestamp_format']}")
        logger.info("=" * 60)
        
        success_count = 0
        failed_count = 0
        
        # 确保目标目录存在
        target_dir = backup_config['target_dir'].lstrip('/')
        if not self.webdav_client.mkdir(target_dir):
            logger.warning(f"创建目标目录失败，但继续尝试备份")
        
        # 备份每个源
        for i, source in enumerate(sources, 1):
            logger.info(f"[{i}/{len(sources)}] 备份源: {source}")
            
            try:
                # 压缩文件/目录
                compressed_file = self.compress_file_or_dir(source)
                if compressed_file is None:
                    logger.warning(f"跳过不存在的源: {source}")
                    failed_count += 1
                    continue
                
                # 上传到WebDAV
                remote_path = f"{target_dir}/{compressed_file.name}" if target_dir else compressed_file.name
                if self.webdav_client.upload_file(remote_path, str(compressed_file)):
                    logger.info(f"✓ 上传成功: {compressed_file.name}")
                    success_count += 1
                else:
                    logger.error(f"✗ 上传失败: {compressed_file.name}")
                    failed_count += 1
                
                # 删除本地临时文件
                try:
                    compressed_file.unlink()
                except Exception as e:
                    logger.warning(f"删除临时压缩文件失败: {e}")
                    
            except Exception as e:
                logger.error(f"备份失败 {source}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                failed_count += 1
        
        # 清理旧备份（按源分别清理）
        logger.info("-" * 40)
        logger.info("开始清理旧备份（按源分别管理）...")
        self.cleanup_old_backups()
        
        # 清理临时文件
        self.cleanup_temp_files()
        
        logger.info("=" * 60)
        logger.info(f"备份完成。成功: {success_count}, 失败: {failed_count}")
        logger.info("=" * 60)
        
        if failed_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)


def test_webdav_connection(config_path: str = "config.yaml"):
    """测试WebDAV连接"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        webdav_config = config['webdav']
        
        print("=" * 60)
        print("测试WebDAV连接")
        print(f"URL: {webdav_config['url']}")
        print(f"用户名: {webdav_config['username']}")
        print("=" * 60)
        
        print("\n1. 测试基本连接...")
        try:
            client = WebDAVClient(
                url=webdav_config['url'],
                username=webdav_config['username'],
                password=webdav_config['password'],
                timeout=webdav_config.get('timeout', 30)
            )
            
            if client.check_connection():
                print("   ✓ 连接成功")
                
                # 测试目录创建
                print("\n2. 测试目录创建...")
                if client.mkdir("test_backup"):
                    print("   ✓ 目录创建成功")
                else:
                    print("   ⚠ 目录创建可能有问题，但可能已存在")
                
                # 测试文件上传
                print("\n3. 测试文件上传...")
                test_content = b"test content"
                test_file = "/tmp/webdav_test.txt"
                with open(test_file, 'wb') as f:
                    f.write(test_content)
                
                if client.upload_file("test_backup/test.txt", test_file):
                    print("   ✓ 文件上传成功")
                else:
                    print("   ✗ 文件上传失败")
                
                # 测试列出文件
                print("\n4. 测试列出文件...")
                files = client.list_files("test_backup")
                if files:
                    print(f"   ✓ 找到 {len(files)} 个文件: {files}")
                else:
                    print("   ⚠ 未找到文件，但可能是正常情况")
                
                # 清理
                print("\n5. 清理测试...")
                client.delete_file("test_backup/test.txt")
                os.remove(test_file)
                print("   ✓ 清理完成")
                
                return True
            else:
                print("   ✗ 连接失败")
                return False
                
        except Exception as e:
            print(f"   ✗ 测试过程中出错: {e}")
            import traceback
            print(traceback.format_exc())
            return False
            
    except Exception as e:
        print(f"配置文件错误: {e}")
        return False


def main():
    """主函数"""
    # 解析命令行参数
    import argparse
    
    parser = argparse.ArgumentParser(description='WebDAV备份工具')
    parser.add_argument('--config', '-c', default='config.yaml', help='配置文件路径')
    parser.add_argument('--test', '-t', action='store_true', help='测试WebDAV连接')
    parser.add_argument('--debug', '-d', action='store_true', help='调试模式，更详细的日志')
    
    args = parser.parse_args()
    
    if args.debug:
        # 设置更详细的日志级别
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    
    if args.test:
        # 测试连接
        if test_webdav_connection(args.config):
            print("\n" + "=" * 60)
            print("连接测试完成！可以开始备份。")
            print("=" * 60)
            sys.exit(0)
        else:
            print("\n" + "=" * 60)
            print("连接测试失败！请检查配置。")
            print("=" * 60)
            sys.exit(1)
    else:
        # 执行备份
        backup = WebDAVBackup(args.config)
        backup.run_backup()


if __name__ == "__main__":
    main()
