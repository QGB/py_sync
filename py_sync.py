import os
import time
import logging
import fnmatch
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import paramiko

class SyncManager:
    """管理 SFTP 连接和文件操作"""
    def __init__(self, remote_dir):
        self.sftp = None
        self.ssh_client = None
        self.remote_dir = remote_dir
        # 保存连接参数以备重连
        self.host = None
        self.port = None
        self.user = None
        self.password = None
        self.key_filename = None

    def connect(self, host, port, user, password=None, key_filename=None):
        """连接到远程服务器"""
        # 保存连接参数
        self.host, self.port, self.user, self.password, self.key_filename = host, port, user, password, key_filename
        try:
            logging.info(f"正在连接到 {user}@{host}:{port}...")
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(self.host, port=self.port, username=self.user, password=self.password, key_filename=self.key_filename, timeout=10)
            self.sftp = self.ssh_client.open_sftp()
            logging.info("SSH/SFTP 连接成功。")
            # 确保远程根目录存在
            self.mkdir_p(self.remote_dir)
            return True
        except paramiko.AuthenticationException:
            logging.error("认证失败！请检查用户名、密码或SSH密钥。")
            self.disconnect()
            return False
        except Exception as e:
            logging.error(f"连接失败: {e}")
            self.disconnect()
            return False

    def disconnect(self):
        """断开连接"""
        if self.sftp:
            self.sftp.close()
            self.sftp = None
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
        logging.info("连接已断开。")

    def is_connected(self):
        """检查是否仍然连接"""
        return self.ssh_client and self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active()

    def _ensure_connection(self):
        """确保连接是活动的，如果不是则重连"""
        if not self.is_connected():
            logging.warning("连接已断开，正在尝试重新连接...")
            self.connect(self.host, self.port, self.user, self.password, self.key_filename)
        return self.is_connected()

    def get_remote_md5(self, remote_path):
        """获取远程文件的 MD5 哈希值"""
        if not self._ensure_connection(): return None
        try:
            with self.sftp.open(remote_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except FileNotFoundError:
            return None
        except Exception as e:
            logging.error(f"获取远程文件 MD5 失败 '{remote_path}': {e}")
            return None

    def upload_file(self, local_path, remote_path):
        """上传文件"""
        if not self._ensure_connection(): return
        try:
            # 确保远程文件的父目录存在
            remote_parent_dir = os.path.dirname(remote_path).replace('\\', '/')
            self.mkdir_p(remote_parent_dir)
            
            logging.info(f"正在上传: {local_path} -> {remote_path}")
            self.sftp.put(local_path, remote_path)
            logging.info(f"上传成功: {remote_path}")
        except Exception as e:
            logging.error(f"上传文件失败 '{local_path}': {e}")

    def delete_file(self, remote_path):
        """删除远程文件"""
        if not self._ensure_connection(): return
        try:
            logging.info(f"正在删除远程文件: {remote_path}")
            self.sftp.remove(remote_path)
            logging.info(f"删除成功: {remote_path}")
        except FileNotFoundError:
            logging.warning(f"尝试删除但文件不存在: {remote_path}")
        except Exception as e:
            logging.error(f"删除远程文件失败 '{remote_path}': {e}")

    def delete_dir(self, remote_path):
        """删除远程目录"""
        if not self._ensure_connection(): return
        try:
            logging.info(f"正在删除远程目录: {remote_path}")
            # Paramiko 的 SFTP 没有递归删除，需要手动实现或执行命令
            # 这里使用 `rm -r` 命令作为简单实现
            self.ssh_client.exec_command(f'rm -rf "{remote_path}"')
            logging.info(f"删除成功: {remote_path}")
        except Exception as e:
            logging.error(f"删除远程目录失败 '{remote_path}': {e}")

    def rename_file_or_dir(self, old_remote_path, new_remote_path):
        """重命名远程文件或目录"""
        if not self._ensure_connection(): return
        try:
            logging.info(f"正在重命名: {old_remote_path} -> {new_remote_path}")
            self.sftp.rename(old_remote_path, new_remote_path)
            logging.info(f"重命名成功")
        except Exception as e:
            logging.error(f"重命名失败: {e}")

    def mkdir_p(self, remote_directory):
        """在远程创建目录，类似 mkdir -p"""
        if not self._ensure_connection(): return
        dirs = []
        while len(remote_directory) > 1:
            try:
                self.sftp.stat(remote_directory)
                break  # 目录已存在
            except FileNotFoundError:
                dirs.append(os.path.basename(remote_directory))
                remote_directory = os.path.dirname(remote_directory)
        
        # 逐级创建不存在的目录
        while len(dirs):
            dir_to_create = dirs.pop()
            remote_directory = os.path.join(remote_directory, dir_to_create).replace('\\', '/')
            try:
                logging.info(f"正在创建远程目录: {remote_directory}")
                self.sftp.mkdir(remote_directory)
            except Exception as e:
                logging.error(f"创建远程目录失败 '{remote_directory}': {e}")
                # 如果创建失败，后续操作可能也无法进行，直接返回
                return

def get_local_md5(local_path):
    """获取本地文件的 MD5 哈希值"""
    try:
        with open(local_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        logging.error(f"获取本地文件 MD5 失败 '{local_path}': {e}")
        return None

def is_path_excluded(relative_path, exclude_patterns):
    """检查给定的相对路径是否匹配任何排除模式"""
    # 将Windows路径分隔符统一为'/'以进行匹配
    path_to_check = relative_path.replace(os.sep, '/')
    for pattern in exclude_patterns:
        # 模式匹配目录 (e.g., "__pycache__/")
        if pattern.endswith('/'):
            # 如果路径是该目录或在该目录内
            if path_to_check == pattern.rstrip('/') or path_to_check.startswith(pattern):
                return True
        # 模式匹配文件名 (e.g., "*.pyc")
        elif fnmatch.fnmatch(os.path.basename(path_to_check), pattern):
            return True
    return False

class SyncEventHandler(FileSystemEventHandler):
    """处理文件系统事件并触发同步操作"""
    def __init__(self, sync_manager, local_dir, remote_dir, exclude_patterns):
        super().__init__()
        self.sync_manager = sync_manager
        self.local_dir = local_dir
        self.remote_dir = remote_dir
        self.exclude_patterns = exclude_patterns

    def _get_remote_path(self, local_path):
        """将本地路径转换为远程路径"""
        relative_path = os.path.relpath(local_path, self.local_dir)
        # 在 Windows 上，relpath 对于同级文件可能返回 `.`
        if relative_path == '.':
            relative_path = os.path.basename(local_path)
        remote_path = os.path.join(self.remote_dir, relative_path).replace('\\', '/')
        return remote_path

    def _is_event_excluded(self, event):
        """检查事件关联的路径是否被排除"""
        # 对于移动事件，如果源或目标任一被排除，则忽略整个事件
        if hasattr(event, 'dest_path'):
            if is_path_excluded(os.path.relpath(event.dest_path, self.local_dir), self.exclude_patterns):
                return True
        return is_path_excluded(os.path.relpath(event.src_path, self.local_dir), self.exclude_patterns)

    def on_created(self, event):
        """文件或目录被创建"""
        if self._is_event_excluded(event): return
        logging.info(f"检测到创建: {'目录' if event.is_directory else '文件'} {event.src_path}")
        remote_path = self._get_remote_path(event.src_path)
        if event.is_directory:
            self.sync_manager.mkdir_p(remote_path)
        else:
            self.sync_manager.upload_file(event.src_path, remote_path)

    def on_modified(self, event):
        """文件被修改"""
        if self._is_event_excluded(event): return
        # 目录修改事件我们忽略
        if event.is_directory:
            return
        
        logging.info(f"检测到修改: {event.src_path}")
        local_path = event.src_path
        remote_path = self._get_remote_path(local_path)

        local_md5 = get_local_md5(local_path)
        remote_md5 = self.sync_manager.get_remote_md5(remote_path)

        if local_md5 and local_md5 != remote_md5:
            logging.info(f"文件内容不一致 (本地: {local_md5[:7]}..., 远程: {str(remote_md5)[:7]}...).")
            self.sync_manager.upload_file(local_path, remote_path)
        elif not remote_md5:
             logging.info(f"远程文件不存在，执行上传。")
             self.sync_manager.upload_file(local_path, remote_path)
        else:
            logging.info("文件内容一致，跳过上传。")

    def on_deleted(self, event):
        """文件或目录被删除"""
        if self._is_event_excluded(event): return
        logging.info(f"检测到删除: {'目录' if event.is_directory else '文件'} {event.src_path}")
        remote_path = self._get_remote_path(event.src_path)
        if event.is_directory:
            self.sync_manager.delete_dir(remote_path)
        else:
            self.sync_manager.delete_file(remote_path)

    def on_moved(self, event):
        """文件或目录被移动/重命名"""
        if self._is_event_excluded(event): return
        logging.info(f"检测到移动/重命名: 从 {event.src_path} 到 {event.dest_path}")
        old_remote_path = self._get_remote_path(event.src_path)
        new_remote_path = self._get_remote_path(event.dest_path)
        self.sync_manager.rename_file_or_dir(old_remote_path, new_remote_path)

def initial_sync(sync_manager, local_dir, remote_dir, exclude_patterns):
    """执行初次全量同步检查"""
    logging.info("--- 开始初始同步检查 ---")
    
    remote_files = {}
    # 递归获取远程所有文件及其属性
    if sync_manager._ensure_connection():
        try:
            # 使用 exec_command 来快速获取文件列表和大小，比逐个 stat 快
            stdin, stdout, stderr = sync_manager.ssh_client.exec_command(f'find "{remote_dir}" -type f -print0')
            remote_file_list = stdout.read().decode().split('\0')
            for remote_path in remote_file_list:
                if remote_path:
                    relative_path = os.path.relpath(remote_path, remote_dir)
                    if not is_path_excluded(relative_path, exclude_patterns):
                        remote_files[relative_path.replace('/', os.sep)] = remote_path
        except Exception as e:
            logging.error(f"获取远程文件列表失败: {e}")


    # 遍历本地文件
    for root, dirs, files in os.walk(local_dir, topdown=True):
        # 从 dirs 列表中原地移除要排除的目录
        # 必须使用切片 dirs[:] 来修改列表
        dirs[:] = [d for d in dirs if not is_path_excluded(os.path.relpath(os.path.join(root, d), local_dir), exclude_patterns)]
        
        # 1. 同步目录
        for dir_name in dirs:
            local_path = os.path.join(root, dir_name)
            relative_path = os.path.relpath(local_path, local_dir)
            if is_path_excluded(relative_path, exclude_patterns): continue
            remote_path = os.path.join(remote_dir, relative_path).replace('\\', '/')
            sync_manager.mkdir_p(remote_path)

        # 2. 同步文件
        for file_name in files:
            local_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(local_path, local_dir)

            if is_path_excluded(relative_path, exclude_patterns):
                # 如果文件被排除，但它存在于远程，则将其从待删除列表中移除
                if relative_path in remote_files:
                    remote_files.pop(relative_path)
                continue
            
            # 如果本地文件在远程文件字典中，则检查哈希值
            if relative_path in remote_files:
                remote_path = remote_files.pop(relative_path) # 从字典中移除，剩下的就是需要删除的
                
                local_md5 = get_local_md5(local_path)
                remote_md5 = sync_manager.get_remote_md5(remote_path)
                
                if local_md5 and local_md5 != remote_md5:
                    logging.info(f"[初始同步] 文件内容不一致: {local_path}")
                    sync_manager.upload_file(local_path, remote_path)
                else:
                    logging.info(f"[初始同步] 文件内容一致，跳过: {local_path}")
            else:
                # 如果本地文件不在远程，则上传
                logging.info(f"[初始同步] 远程不存在，上传新文件: {local_path}")
                remote_path = os.path.join(remote_dir, relative_path).replace('\\', '/')
                sync_manager.upload_file(local_path, remote_path)

    # 3. 删除远程多余的文件
    # remote_files 字典中剩下的就是本地没有的
    for relative_path, remote_path in remote_files.items():
        logging.info(f"[初始同步] 本地不存在，删除远程文件: {remote_path}")
        sync_manager.delete_file(remote_path)

    logging.info("--- 初始同步检查完成 ---")


if __name__ == "__main__":
    import argparse
    import re
    import getpass

    parser = argparse.ArgumentParser(
        description="纯Python实现的差异同步工具，通过SSH/SFTP将本地文件夹实时同步到远程服务器。",
        epilog='示例: python py_sync.py "qgb@101.36.121.63:/home/qgb/" -p 22 -k "C:/Users/user/.ssh/id_rsa"'
    )
    parser.add_argument('remote_target', help='远程目标，格式为 "user@host:/path/to/dir"')
    parser.add_argument('local_dir', nargs='?', default=os.getcwd(), help='要同步的本地文件夹 (默认为当前目录)')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH端口 (默认为 22)')
    parser.add_argument('-k', '--key', type=str, default=None, help='SSH私钥文件路径 (如果使用密钥登录)')
    parser.add_argument('--log-file', type=str, default=None, help='将日志输出到指定文件')
    parser.add_argument('--exclude', action='append', default=[], help='要排除的文件/目录模式 (例如 "*.pyc", "__pycache__/"). 可多次使用。')

    args = parser.parse_args()

    # --- 日志配置 ---
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'
    log_handlers = [logging.StreamHandler()] # 默认输出到控制台
    if args.log_file:
        log_handlers.append(logging.FileHandler(args.log_file, encoding='utf-8'))
    
    logging.basicConfig(level=logging.INFO,
                        format=log_format,
                        datefmt=log_datefmt,
                        handlers=log_handlers)

    # 解析 remote_target
    match = re.match(r'([^@]+)@([^:]+):(.+)', args.remote_target)
    if not match:
        logging.error('远程目标格式错误！请使用 "user@host:/path/to/dir" 格式。')
        exit(1)

    REMOTE_USER, REMOTE_HOST, REMOTE_DIR = match.groups()
    LOCAL_DIR = os.path.abspath(args.local_dir)
    REMOTE_PORT = args.port
    KEY_FILENAME = args.key
    EXCLUDE_PATTERNS = args.exclude

    if not os.path.isdir(LOCAL_DIR):
        logging.error(f"本地目录不存在: {LOCAL_DIR}")
        exit(1)

    # 获取密码
    REMOTE_PASSWORD = None
    if not KEY_FILENAME:
        try:
            REMOTE_PASSWORD = getpass.getpass(f"请输入 {REMOTE_USER}@{REMOTE_HOST} 的密码: ")
        except Exception as e:
            logging.error(f"无法读取密码: {e}")
            exit(1)

    # 实例化并连接
    sync_manager = SyncManager(remote_dir=REMOTE_DIR)
    if not sync_manager.connect(REMOTE_HOST, REMOTE_PORT, REMOTE_USER, password=REMOTE_PASSWORD, key_filename=KEY_FILENAME):
        logging.error("无法连接到服务器，程序退出。请检查配置。")
        exit(1)

    # 执行初始同步
    initial_sync(sync_manager, LOCAL_DIR, REMOTE_DIR, EXCLUDE_PATTERNS)

    # 创建并启动监控
    event_handler = SyncEventHandler(sync_manager, LOCAL_DIR, REMOTE_DIR, EXCLUDE_PATTERNS)
    observer = Observer()
    observer.schedule(event_handler, LOCAL_DIR, recursive=True)
    
    logging.info(f"开始监控文件夹: {LOCAL_DIR}")
    observer.start()
    try:
        while True:
            time.sleep(5)
            # 定期检查连接状态
            if not sync_manager.is_connected():
                logging.warning("主循环检测到连接断开，尝试重连...")
                sync_manager.connect(REMOTE_HOST, REMOTE_PORT, REMOTE_USER, password=REMOTE_PASSWORD, key_filename=KEY_FILENAME)

    except KeyboardInterrupt:
        logging.info("收到退出信号，正在停止...")
        observer.stop()
    finally:
        observer.join()
        sync_manager.disconnect()
        logging.info("程序已干净地退出。")
