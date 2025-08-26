package collect

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "collect"

// 全局实例管理器，确保同一文件只有一个实例
var (
	instancesMu sync.RWMutex
	instances   = make(map[string]*collect)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	Format    string `yaml:"format"`    // domain, full, keyword
	FilePath  string `yaml:"file_path"` // 文件路径
	Operation string `yaml:"operation"` // add(默认), delete
}

var _ sequence.Executable = (*collectWrapper)(nil)

// 写入操作类型
type writeOp struct {
	action string // "add" 或 "rewrite"
	entry  string // 单条记录（add时使用）
}

// collect结构
type collect struct {
	filePath string
	
	// 锁机制
	cacheMu sync.RWMutex // 保护内存缓存
	fileMu  sync.Mutex   // 保护文件操作的原子性
	
	// 数据结构
	cache map[string]bool // 内存缓存，启动时加载文件内容
	
	// 异步写入
	writeQueue chan writeOp   // 统一的写入队列
	stopChan   chan struct{} // 停止信号
	wg         sync.WaitGroup
	
	// 引用计数
	refCount int32
}

// 操作包装器
type collectWrapper struct {
	instance  *collect
	format    string
	operation string
}

func (cw *collectWrapper) Exec(ctx context.Context, qCtx *query_context.Context) error {
	question := qCtx.QQuestion()
	domain := strings.TrimSuffix(question.Name, ".")
	
	if domain == "" {
		return nil
	}

	// 根据格式生成字符串
	var entry string
	switch cw.format {
	case "domain":
		entry = fmt.Sprintf("domain:%s", domain)
	case "full":
		entry = fmt.Sprintf("full:%s", domain)
	case "keyword":
		entry = fmt.Sprintf("keyword:%s", domain)
	default:
		entry = fmt.Sprintf("full:%s", domain)
	}

	// 根据操作类型执行相应操作
	switch cw.operation {
	case "delete":
		return cw.instance.deleteEntry(entry)
	default:
		return cw.instance.addEntry(entry)
	}
}

// 添加条目
func (c *collect) addEntry(entry string) error {
	c.cacheMu.Lock()
	// 检查是否已存在于内存缓存中
	if c.cache[entry] {
		c.cacheMu.Unlock()
		return nil // 已存在，无需重复添加
	}
	
	// 添加到内存缓存
	c.cache[entry] = true
	c.cacheMu.Unlock()
	
	// 异步追加到文件，带重试机制
	go func() {
		for retries := 0; retries < 3; retries++ {
			select {
			case c.writeQueue <- writeOp{action: "add", entry: entry}:
				return // 成功发送
			default:
				if retries < 2 {
					// 等待一小段时间后重试
					time.Sleep(time.Millisecond * 10)
					continue
				}
				// 最后一次重试失败，保留错误日志
				log.Printf("[COLLECT] ERROR: failed to queue add operation after 3 retries for %s", entry)
			}
		}
	}()
	
	// log.Printf("[COLLECT] ADD %s to %s", entry, c.filePath)
	return nil
}

// 删除条目 
func (c *collect) deleteEntry(entry string) error {
	c.cacheMu.Lock()
	// 检查条目是否存在
	if !c.cache[entry] {
		c.cacheMu.Unlock()
		return nil // 不存在，无需删除
	}
	
	// 从内存缓存中删除
	delete(c.cache, entry)
	c.cacheMu.Unlock()
	
	// 异步触发文件重写，带重试机制
	go func() {
		for retries := 0; retries < 5; retries++ { // delete操作更重要，多重试几次
			select {
			case c.writeQueue <- writeOp{action: "rewrite"}:
				return // 成功发送
			default:
				if retries < 4 {
					// 等待更长时间后重试
					time.Sleep(time.Millisecond * 50)
					continue
				}
				// 最后一次重试失败，保留错误日志
				log.Printf("[COLLECT] ERROR: failed to queue rewrite operation after 5 retries")
			}
		}
	}()
	
	// log.Printf("[COLLECT] DEL %s for %s", entry, c.filePath)
	return nil
}

// 简化的写入处理器
func (c *collect) writeProcessor() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		
		for {
			select {
			case op := <-c.writeQueue:
				c.handleWriteOperation(op)
			case <-c.stopChan:
				// 处理剩余操作
				for {
					select {
					case op := <-c.writeQueue:
						c.handleWriteOperation(op)
					default:
						return
					}
				}
			}
		}
	}()
}

// 简化的写入操作处理
func (c *collect) handleWriteOperation(op writeOp) {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()

	switch op.action {
	case "add":
		c.appendToFile(op.entry)
	case "rewrite":
		c.rewriteEntireFile()
	}
}

// 追加到文件
func (c *collect) appendToFile(entry string) {
	file, err := os.OpenFile(c.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// 保留错误日志
		log.Printf("[COLLECT] ERROR: failed to open file for append: %v", err)
		return
	}
	defer file.Close()
	
	if _, err := file.WriteString(entry + "\n"); err != nil {
		// 保留错误日志
		log.Printf("[COLLECT] ERROR: failed to append entry: %v", err)
	}
}

// 启动后台处理goroutine
func (c *collect) startBackgroundProcessor() {
	c.writeProcessor()
}

// 获取或创建文件实例
func getOrCreateInstance(filePath string) (*collect, error) {
	instancesMu.Lock()
	defer instancesMu.Unlock()
	
	instance, exists := instances[filePath]
	if exists {
		// 增加引用计数
		instance.refCount++
		return instance, nil
	}
	
	// 创建新实例
	instance = &collect{
		filePath:   filePath,
		writeQueue: make(chan writeOp, 1000), // 增大缓冲队列
		stopChan:   make(chan struct{}),
		refCount:   1,
	}
	
	// 初始化内存缓存并加载文件内容
	instance.cache = make(map[string]bool)
	if err := instance.loadFileToCache(); err != nil {
		return nil, fmt.Errorf("failed to load file to cache: %w", err)
	}
	
	// 启动后台写入处理
	instance.startBackgroundProcessor()
	
	// 注册到全局管理器
	instances[filePath] = instance
	
	return instance, nil
}

// 包装器的关闭方法
func (cw *collectWrapper) Close() error {
	instancesMu.Lock()
	defer instancesMu.Unlock()
	
	cw.instance.refCount--
	if cw.instance.refCount <= 0 {
		// 最后一个引用，关闭实例
		delete(instances, cw.instance.filePath)
		return cw.instance.close()
	}
	return nil
}

// 实例的内部关闭方法
func (c *collect) close() error {
	if c.stopChan != nil {
		close(c.stopChan)
	}
	c.wg.Wait()
	return nil
}

// 重写整个文件 - 根据内存缓存重建文件
func (c *collect) rewriteEntireFile() {
	c.cacheMu.RLock()
	// 复制当前缓存状态
	var entries []string
	for entry := range c.cache {
		entries = append(entries, entry)
	}
	c.cacheMu.RUnlock()
	
	// 使用临时文件+原子性重命名，确保触发fsnotify事件
	tempFilePath := c.filePath + ".tmp"
	tempFile, err := os.OpenFile(tempFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		// 保留错误日志
		log.Printf("[COLLECT] ERROR: failed to create temp file: %v", err)
		return
	}
	
	// 写入所有条目到临时文件
	for _, entry := range entries {
		if _, err := tempFile.WriteString(entry + "\n"); err != nil {
			tempFile.Close()
			os.Remove(tempFilePath)
			// 保留错误日志
			log.Printf("[COLLECT] ERROR: failed to write entry to temp file: %v", err)
			return
		}
	}
	tempFile.Close()
	
	// 原子性重命名，这会触发fsnotify的WRITE事件
	if err := os.Rename(tempFilePath, c.filePath); err != nil {
		os.Remove(tempFilePath)
		// 保留错误日志
		log.Printf("[COLLECT] ERROR: failed to rename temp file: %v", err)
		return
	}
	
	// log.Printf("[COLLECT] REWRITE_FILE completed, %d entries written", len(entries))
}

func (c *collect) loadFileToCache() error {
	file, err := os.Open(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，返回空缓存
		}
		return fmt.Errorf("failed to open file for reading: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 设置较大的缓冲区以处理大文件
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // 1MB 缓冲区

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			c.cache[line] = true
		}
	}

	return scanner.Err()
}

func Init(_ *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	if a.FilePath == "" {
		return nil, fmt.Errorf("file_path is required")
	}

	format := strings.ToLower(a.Format)
	if format != "domain" && format != "full" && format != "keyword" {
		format = "full"
	}

	operation := strings.ToLower(a.Operation)
	if operation != "add" && operation != "delete" {
		operation = "add"
	}

	// 获取或创建共享实例
	instance, err := getOrCreateInstance(a.FilePath)
	if err != nil {
		return nil, err
	}

	// 返回包装器
	return &collectWrapper{
		instance:  instance,
		format:    format,
		operation: operation,
	}, nil
}

