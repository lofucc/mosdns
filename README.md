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

域名收集插件，用于收集和管理DNS查询中的域名，支持添加和删除操作，具有高性能缓存机制。

#### 核心特性

- **双向操作**：支持域名的添加和删除操作
- **三种格式**：
  - `domain`：域名格式 `domain:example.com`
  - `full`：完整格式 `full:example.com` 
  - `keyword`：关键词格式 `keyword:example.com`
- **高性能架构**：
  - 启动时加载文件内容到内存缓存
  - 添加操作：内存检查去重 + 异步追加写入
  - 删除操作：内存立即删除 + 异步文件重写
- **数据一致性**：
  - 多实例共享机制，同文件只有一个实例
  - 异步写入队列，容量1000，带重试机制
  - 临时文件+原子重命名，确保文件操作安全
- **自动热加载**：配合 `domain_set` 插件实现文件变化自动重载

#### 配置参数

```yaml
plugins:
  - tag: domain_collector
    type: collect
    args:
      format: full                    # 域名格式：domain/full/keyword，默认full
      file_path: /path/to/domains.txt # 文件路径（必填）
      operation: add                  # 操作类型：add/delete，默认add
```