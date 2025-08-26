/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
	Format      string `yaml:"format"`       // domain, full, keyword
	FilePath    string `yaml:"file_path"`    // 文件路径
	Operation   string `yaml:"operation"`    // add(默认), delete
	FlushPeriod int    `yaml:"flush_period"` // 文件刷新间隔(秒)，默认60秒
}

var _ sequence.Executable = (*collectWrapper)(nil)

type FileOperation struct {
	Type  string // "add" or "delete"
	Entry string
}

type collect struct {
	filePath string
	
	// 统一锁机制
	cacheMu sync.RWMutex // 缓存读写锁，保护内存操作
	fileMu  sync.Mutex   // 文件操作锁，保护所有文件IO
	
	// 数据结构
	cache   map[string]bool // 主缓存
	deleted map[string]bool // 待删除标记
	
	// 统一的文件操作队列
	fileOpQueue chan FileOperation // 统一的文件操作队列
	flushTicker *time.Ticker        // 定期刷新
	stopChan    chan struct{}       // 停止信号
	wg          sync.WaitGroup      // 等待goroutine结束
	
	// 批量操作缓冲
	pendingAdds    []string // 待追加的条目
	pendingDeletes map[string]bool // 待删除的条目
	
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
		entry = fmt.Sprintf("full:%s", domain) // 默认为full格式
	}

	// 根据操作类型执行相应操作
	switch cw.operation {
	case "delete":
		return cw.instance.deleteEntry(entry)
	default: // "add" 或其他值都当作添加
		return cw.instance.addEntry(entry)
	}
}

// 添加条目
func (c *collect) addEntry(entry string) error {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// 检查是否已存在于缓存中（未被删除标记）
	if c.cache[entry] && !c.deleted[entry] {
		return nil // 已存在且未被删除标记，无需添加
	}

	// 如果在删除队列中，取消删除操作
	if c.deleted[entry] {
		delete(c.deleted, entry)
		delete(c.pendingDeletes, entry)
		c.cache[entry] = true
		log.Printf("[COLLECT] CANCEL_DEL %s", entry)
		return nil // 取消删除，不需要重复写入文件
	}

	// 新条目，添加到缓存
	c.cache[entry] = true

	// 通知文件操作队列（非阻塞）
	select {
	case c.fileOpQueue <- FileOperation{Type: "add", Entry: entry}:
	default:
		// 队列满时，添加到待处理列表，等待下次批量处理
		c.pendingAdds = append(c.pendingAdds, entry)
	}
	
	log.Printf("[COLLECT] ADD %s", entry)
	return nil
}

// 删除条目
func (c *collect) deleteEntry(entry string) error {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// 检查条目是否存在且未被标记删除
	if !c.cache[entry] || c.deleted[entry] {
		return nil // 不存在或已标记删除，无需重复操作
	}

	// 立即更新内存状态：保留在cache中但标记为deleted
	// 这样addEntry可以检测到并取消删除操作
	c.deleted[entry] = true
	c.pendingDeletes[entry] = true

	// 通知文件操作队列（非阻塞）
	select {
	case c.fileOpQueue <- FileOperation{Type: "delete", Entry: entry}:
	default:
		// 队列满时跳过，等待下次定期刷新处理
	}

	log.Printf("[COLLECT] DEL %s", entry)
	return nil
}

// 统一的文件操作处理器
func (c *collect) fileOperationProcessor() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		
		for {
			select {
			case op := <-c.fileOpQueue:
				c.handleFileOperation(op)
			case <-c.flushTicker.C:
				c.batchFlush()
			case <-c.stopChan:
				// 处理剩余操作
				for {
					select {
					case op := <-c.fileOpQueue:
						c.handleFileOperation(op)
					default:
						goto exit
					}
				}
				exit:
				c.batchFlush() // 最后一次刷新
				return
			}
		}
	}()
}

// 处理单个文件操作
func (c *collect) handleFileOperation(op FileOperation) {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()

	switch op.Type {
	case "add":
		c.appendToFile(op.Entry)
	case "delete":
		// 删除操作暂存，等待批量处理
		c.cacheMu.Lock()
		c.pendingDeletes[op.Entry] = true
		c.cacheMu.Unlock()
		log.Printf("[COLLECT] DELETE_QUEUED %s", op.Entry)
	}
}

// 追加到文件
func (c *collect) appendToFile(entry string) {
	file, err := os.OpenFile(c.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return // 静默处理错误
	}
	defer file.Close()
	file.WriteString(entry + "\n")
}

// 启动后台处理goroutine
func (c *collect) startBackgroundProcessor() {
	c.fileOperationProcessor()
}

// 获取或创建文件实例
func getOrCreateInstance(filePath string, flushPeriod int) (*collect, error) {
	instancesMu.Lock()
	defer instancesMu.Unlock()
	
	instance, exists := instances[filePath]
	if exists {
		// 增加引用计数
		instance.refCount++
		return instance, nil
	}
	
	// 创建新实例
	if flushPeriod <= 0 {
		flushPeriod = 60
	}
	
	instance = &collect{
		filePath:       filePath,
		fileOpQueue:    make(chan FileOperation, 1000),
		stopChan:       make(chan struct{}),
		flushTicker:    time.NewTicker(time.Duration(flushPeriod) * time.Second),
		pendingDeletes: make(map[string]bool),
		refCount:       1,
	}
	
	// 立即加载文件到内存
	instance.cache = make(map[string]bool)
	instance.deleted = make(map[string]bool)
	if err := instance.loadFileToCache(); err != nil {
		return nil, fmt.Errorf("failed to load file to cache: %w", err)
	}
	
	// 启动后台处理
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
	if c.flushTicker != nil {
		c.flushTicker.Stop()
	}
	c.wg.Wait()
	return nil
}

// 批量刷新操作
func (c *collect) batchFlush() {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	
	c.cacheMu.Lock()
	
	// 处理待追加的条目
	if len(c.pendingAdds) > 0 {
		c.batchAppendToFile(c.pendingAdds)
		c.pendingAdds = c.pendingAdds[:0] // 清空
	}
	
	// 检查是否有删除操作需要处理
	if len(c.pendingDeletes) == 0 {
		c.cacheMu.Unlock()
		return
	}
	
	// 复制待删除列表
	toDelete := make(map[string]bool)
	for k := range c.pendingDeletes {
		toDelete[k] = true
	}
	c.cacheMu.Unlock()

	// 执行文件重写
	log.Printf("[COLLECT] REWRITE_FILE start, deleting %d entries", len(toDelete))
	err := c.rewriteFileWithDeletes(toDelete)
	if err != nil {
		log.Printf("[COLLECT] REWRITE_FILE failed: %v", err)
		return // 出错时保留删除标记，下次再试
	}

	// 清理删除标记和缓存
	c.cacheMu.Lock()
	for k := range toDelete {
		delete(c.deleted, k)
		delete(c.pendingDeletes, k)
		delete(c.cache, k) // 从缓存中完全移除
		log.Printf("[COLLECT] DELETE_DONE %s", k)
	}
	c.cacheMu.Unlock()
	log.Printf("[COLLECT] REWRITE_FILE completed, %d entries deleted", len(toDelete))
}

// 批量追加到文件
func (c *collect) batchAppendToFile(entries []string) {
	file, err := os.OpenFile(c.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return // 静默处理错误
	}
	defer file.Close()
	
	for _, entry := range entries {
		file.WriteString(entry + "\n")
	}
}

// 重写文件，排除删除的条目
func (c *collect) rewriteFileWithDeletes(toDelete map[string]bool) error {
	// 读取现有文件
	file, err := os.Open(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，无需处理
		}
		return err
	}

	var validLines []string
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !toDelete[line] {
			validLines = append(validLines, line)
		}
	}
	file.Close()

	if err := scanner.Err(); err != nil {
		return err
	}

	// 写入临时文件
	tmpFile := c.filePath + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	for _, line := range validLines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			f.Close()
			os.Remove(tmpFile)
			return err
		}
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}

	// 原子替换
	return os.Rename(tmpFile, c.filePath)
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
		format = "full" // 默认值
	}

	operation := strings.ToLower(a.Operation)
	if operation != "add" && operation != "delete" {
		operation = "add" // 默认值
	}

	// 获取或创建共享实例
	instance, err := getOrCreateInstance(a.FilePath, a.FlushPeriod)
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

