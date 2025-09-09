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

package domain_set

import (
	"bytes"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/fsnotify/fsnotify"
	"os"
)

const PluginType = "domain_set"

// 注册插件
func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	m, err := NewDomainSet(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	return m, nil
}

type Args struct {
	Exps       []string `yaml:"exps"`
	Sets       []string `yaml:"sets"`
	Files      []string `yaml:"files"`
	AutoReload bool     `yaml:"auto_reload"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	// 优化: 按文件分别维护matcher，支持增量更新
	fileMatchers map[string]domain.Matcher[struct{}] // key: 文件路径, value: 该文件的matcher
	setMatchers  []domain.Matcher[struct{}]           // 来自其他plugin提供的matcher
	expMatcher   domain.Matcher[struct{}]             // 来自args.Exps的matcher
	
	// 无锁缓存优化: 缓存最新的MatcherGroup，避免每次查询都重建
	cachedMatcher atomic.Value // 存储 MatcherGroup
	
	watcher *fsnotify.Watcher
	files   []string
	mx      sync.RWMutex  // 只在更新时使用，查询时无锁
	bp      *coremain.BP
	args    *Args
	
	// 防抖机制：记录文件的最后修改时间，避免重复加载
	lastReloadTime map[string]time.Time
	reloadMutex    sync.Mutex
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	start := time.Now()
	
	// 无锁读取缓存的MatcherGroup
	if cached := d.cachedMatcher.Load(); cached != nil {
		elapsed := time.Since(start)
		// 只在首次或耗时异常时记录日志
		if elapsed > 100*time.Microsecond {
			log.Printf("[DOMAIN_SET_PERF] GetDomainMatcher cached: elapsed=%v", elapsed)
		}
		return cached.(MatcherGroup)
	}
	
	// 缓存未命中，需要重建（正常情况下只在初始化和文件变更时发生）
	d.rebuildCache()
	
	// 再次尝试从缓存读取
	if cached := d.cachedMatcher.Load(); cached != nil {
		elapsed := time.Since(start)
		log.Printf("[DOMAIN_SET_PERF] GetDomainMatcher rebuilt: elapsed=%v", elapsed)
		return cached.(MatcherGroup)
	}
	
	// 如果仍然失败，返回空匹配器（不应该发生）
	log.Printf("[DOMAIN_SET_PERF] GetDomainMatcher failed to rebuild cache")
	return MatcherGroup{}
}

// rebuildCache 重建缓存的MatcherGroup（外部调用，需要获取锁）
func (d *DomainSet) rebuildCache() {
	d.mx.RLock()
	defer d.mx.RUnlock()
	d.rebuildCacheUnsafe()
}

// rebuildCacheUnsafe 重建缓存的MatcherGroup（内部调用，已持有锁）
func (d *DomainSet) rebuildCacheUnsafe() {
	// 性能优化：精确预分配容量，避免slice扩容
	capacity := len(d.fileMatchers) + len(d.setMatchers)
	if d.expMatcher != nil {
		capacity++
	}
	allMatchers := make([]domain.Matcher[struct{}], 0, capacity)
	
	// 直接添加表达式matcher，无需检查
	if d.expMatcher != nil {
		allMatchers = append(allMatchers, d.expMatcher)
	}
	
	// 直接添加所有非nil的fileMatchers，移除所有类型断言和Len()检查
	for _, matcher := range d.fileMatchers {
		if matcher != nil {
			allMatchers = append(allMatchers, matcher)
		}
	}
	
	// 批量添加setMatchers
	allMatchers = append(allMatchers, d.setMatchers...)
	
	// 原子性更新缓存
	newMatcherGroup := MatcherGroup(allMatchers)
	d.cachedMatcher.Store(newMatcherGroup)
}

// NewDomainSet inits a DomainSet from given args.
func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{
		bp:             bp,
		args:           args,
		fileMatchers:   make(map[string]domain.Matcher[struct{}]), // 初始化文件matcher映射
		lastReloadTime: make(map[string]time.Time),                 // 初始化防抖时间记录
	}

	// 优化: 分别处理表达式和文件
	// 1. 处理表达式（args.Exps）
	if len(args.Exps) > 0 {
		expMatcher := domain.NewDomainMixMatcher()
		if err := LoadExps(args.Exps, expMatcher); err != nil {
			return nil, err
		}
		ds.expMatcher = expMatcher
	}

	// 2. 按文件分别创建matcher
	for _, file := range args.Files {
		fileMatcher := domain.NewDomainMixMatcher()
		if err := LoadFile(file, fileMatcher); err != nil {
			return nil, fmt.Errorf("failed to load file %s: %w", file, err)
		}
		ds.fileMatchers[file] = fileMatcher
	}

	// 3. 处理其他插件提供的matcher
	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		matcher := provider.GetDomainMatcher()
		ds.setMatchers = append(ds.setMatchers, matcher)
	}

	// 初始化缓存
	ds.rebuildCache()

	// 如果启用了自动重载且有文件需要监控
	if args.AutoReload && len(args.Files) > 0 {
		ds.files = args.Files
		if err := ds.startFileWatcher(); err != nil {
			return nil, fmt.Errorf("failed to start file watcher: %w", err)
		}
	}

	return ds, nil
}

func LoadExpsAndFiles(exps []string, fs []string, m *domain.MixMatcher[struct{}]) error {
	if err := LoadExps(exps, m); err != nil {
		return err
	}
	if err := LoadFiles(fs, m); err != nil {
		return err
	}
	return nil
}

func LoadExps(exps []string, m *domain.MixMatcher[struct{}]) error {
	for i, exp := range exps {
		if err := m.Add(exp, struct{}{}); err != nil {
			return fmt.Errorf("failed to load expression #%d %s, %w", i, exp, err)
		}
	}
	return nil
}

func LoadFiles(fs []string, m *domain.MixMatcher[struct{}]) error {
	for i, f := range fs {
		if err := LoadFile(f, m); err != nil {
			return fmt.Errorf("failed to load file #%d %s, %w", i, f, err)
		}
	}
	return nil
}

func LoadFile(f string, m *domain.MixMatcher[struct{}]) error {
	if len(f) > 0 {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		
		if err := domain.LoadFromTextReader(m, bytes.NewReader(b), nil); err != nil {
			return err
		}
	}
	return nil
}

// startFileWatcher 启动文件监控器
func (d *DomainSet) startFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	
	d.watcher = watcher
	
	// 监控所有文件
	for _, file := range d.files {
		if err := watcher.Add(file); err != nil {
			return fmt.Errorf("failed to watch file %s: %w", file, err)
		}
		// log.Printf("[DOMAIN_SET] WATCH %s", file)
	}
	
	go d.watchFiles()
	
	return nil
}

// watchFiles 监控文件变化
func (d *DomainSet) watchFiles() {
	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}
			
			// 优化: 精确重载变化的文件，而不是所有文件
			// 主要监听Write和Create事件，兼容collect插件的直接写入模式
			if event.Op&fsnotify.Write == fsnotify.Write || 
			   event.Op&fsnotify.Create == fsnotify.Create {
				// log.Printf("[DOMAIN_SET] EVENT %s: %v", event.Name, event.Op)
				d.reloadSingleFile(event.Name) // 只重载变化的文件
			}
			
		case err, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
			// 忽略错误但继续运行
			_ = err
		}
	}
}

// reloadSingleFile 优化: 只重新加载指定文件，带防抖机制
func (d *DomainSet) reloadSingleFile(filePath string) {
	start := time.Now()
	
	// 防抖检查
	d.reloadMutex.Lock()
	now := time.Now()
	lastTime, exists := d.lastReloadTime[filePath]
	
	// 如果距离上次重载不到500ms，则跳过
	debounceInterval := 500 * time.Millisecond
	if exists && now.Sub(lastTime) < debounceInterval {
		d.reloadMutex.Unlock()
		// log.Printf("[DOMAIN_SET] SKIP %s (debounced)", filePath)
		return
	}
	
	// 更新最后重载时间
	d.lastReloadTime[filePath] = now
	d.reloadMutex.Unlock()
	
	debounceEnd := time.Now()
	
	d.mx.Lock()
	lockAcquired := time.Now()
	
	// 检查是否为我们监控的文件
	if _, monitored := d.fileMatchers[filePath]; !monitored {
		d.mx.Unlock()
		return // 不是我们监控的文件，忽略
	}
		
	// 为该文件创建新的matcher
	newFileMatcher := domain.NewDomainMixMatcher()
	if err := LoadFile(filePath, newFileMatcher); err != nil {
		// 加载失败，保持原有状态
		// 保留错误日志以便问题排查
		log.Printf("[DOMAIN_SET] ERROR %s: %v", filePath, err)
		d.mx.Unlock()
		return
	}
	
	// 原子性更新该文件的matcher
	d.fileMatchers[filePath] = newFileMatcher
	
	// 立即重建缓存，避免下次查询时的锁竞争
	d.rebuildCacheUnsafe() // 已经持有写锁，使用内部版本
	
	d.mx.Unlock()
	end := time.Now()
	
	// 记录文件重载性能
	totalTime := end.Sub(start)
	debounceTime := debounceEnd.Sub(start)
	lockWait := lockAcquired.Sub(debounceEnd)
	loadTime := end.Sub(lockAcquired)
	
	log.Printf("[DOMAIN_SET_RELOAD] File reload: %s, total=%v (debounce=%v, lockWait=%v, loadTime=%v)", 
		filePath, totalTime, debounceTime, lockWait, loadTime)
}

// reloadFiles 重新加载所有文件（保留兼容性）
func (d *DomainSet) reloadFiles() {
	d.mx.Lock()
	defer d.mx.Unlock()
	
	// 重新加载表达式
	if len(d.args.Exps) > 0 {
		expMatcher := domain.NewDomainMixMatcher()
		if err := LoadExps(d.args.Exps, expMatcher); err == nil {
			d.expMatcher = expMatcher
		}
	}
	
	// 重新加载所有文件
	for _, file := range d.args.Files {
		fileMatcher := domain.NewDomainMixMatcher()
		if err := LoadFile(file, fileMatcher); err == nil {
			d.fileMatchers[file] = fileMatcher
		}
	}
	
	// 重新添加其他插件提供的matcher
	newSetMatchers := make([]domain.Matcher[struct{}], 0, len(d.args.Sets))
	for _, tag := range d.args.Sets {
		provider, _ := d.bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider != nil {
			matcher := provider.GetDomainMatcher()
			newSetMatchers = append(newSetMatchers, matcher)
		}
	}
	d.setMatchers = newSetMatchers
}

// Close 关闭文件监控器
func (d *DomainSet) Close() error {
	if d.watcher != nil {
		return d.watcher.Close()
	}
	return nil
}
