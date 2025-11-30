纯Python实现差异同步方案   通过 ssh 【参考rsync，windows可用】

cmd中执行，不要在ipython中【不显示log】

`C:\QGB\Anaconda3\python.exe D:\test\github\py_sync\py_sync.py "user@ip:/home/dir" D:\local_dir -k C:\Users\Administrator\.ssh\privateKey.pem`


```
2025-11-30 23:41:10 - INFO - 正在连接到 user@ip
2025-11-30 23:41:10 - INFO - Connected (version 2.0, client OpenSSH_9.6p1)
2025-11-30 23:41:10 - INFO - Authentication (publickey) successful!
2025-11-30 23:41:11 - INFO - [chan 0] Opened sftp connection (server version 3)
2025-11-30 23:41:11 - INFO - SSH/SFTP 连接成功。
2025-11-30 23:41:11 - INFO - --- 开始初始同步检查 ---
2025-11-30 23:41:11 - INFO - [初始同步] 文件内容一致，跳过:```