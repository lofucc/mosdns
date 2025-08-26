# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)


# 自用修改

## 修改的插件

### domain_set

- 支持自动重载 auto_reload

```yaml
plugins:
  - tag: domain_set
    type: domain_set
    args:
      auto_reload: true
      files:
        - /path/to/domain_set.txt
```

## 新增插件

### collect

域名收集插件，用于收集DNS查询中的域名并保存到文件，支持去重和高性能缓存。

#### 功能特性

- **三种格式支持**：
  - `domain`：原始域名格式，如 `domain:example.com`
  - `full`：完整格式，如 `full:example.com`
  - `keyword`：关键词格式，如 `keyword:example.com`
- **高性能缓存**：使用内存缓存避免重复文件读取，支持大文件场景（10万+条目）
- **自动去重**：检测已存在的域名条目，避免重复写入
- **并发安全**：使用读写锁确保多线程安全
- **追加写入**：新条目追加到文件末尾，不影响现有内容

#### 配置方式

**完整配置（推荐）：**
```yaml
plugins:
  - tag: domain_collector
    type: collect
    args:
      format: full                           # domain, full, keyword
      file_path: /path/to/collected_domains.txt
      
# 在规则中使用
rules:
  - exec: $domain_collector
```
