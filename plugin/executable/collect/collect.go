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
	"os"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "collect"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type Args struct {
	Format   string `yaml:"format"`    // domain, full, keyword
	FilePath string `yaml:"file_path"` // 文件路径
}

var _ sequence.Executable = (*collect)(nil)

type collect struct {
	format   string
	filePath string
	mu       sync.RWMutex
	cache    map[string]bool // 缓存已存在的条目，避免重复读取文件
}

func (c *collect) Exec(ctx context.Context, qCtx *query_context.Context) error {
	question := qCtx.QQuestion()
	domain := strings.TrimSuffix(question.Name, ".")
	
	if domain == "" {
		return nil
	}

	// 根据格式生成字符串
	var entry string
	switch c.format {
	case "domain":
		entry = domain
	case "full":
		entry = fmt.Sprintf("full:%s", domain)
	case "keyword":
		entry = fmt.Sprintf("keyword:%s", domain)
	default:
		entry = domain // 默认为domain格式
	}

	// 检查并写入文件
	return c.checkAndWrite(entry)
}

func (c *collect) checkAndWrite(entry string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查缓存
	if c.cache[entry] {
		return nil
	}

	// 读取文件内容到缓存（如果缓存为空）
	if c.cache == nil {
		c.cache = make(map[string]bool)
		if err := c.loadFileToCache(); err != nil {
			return err
		}
	}

	// 再次检查缓存
	if c.cache[entry] {
		return nil
	}

	// 追加写入文件
	file, err := os.OpenFile(c.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(entry + "\n"); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	// 更新缓存
	c.cache[entry] = true
	
	return nil
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
		format = "domain" // 默认值
	}

	return &collect{
		format:   format,
		filePath: a.FilePath,
	}, nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// 默认使用domain格式，只需要传文件路径
	return &collect{
		format:   "domain",
		filePath: s,
	}, nil
}