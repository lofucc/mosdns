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
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/fsnotify/fsnotify"
	"os"
)

const PluginType = "domain_set"

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
	// 动态matcher组，支持热重载
	dynamicGroup *DynamicMatcherGroup
	
	// 可选的热加载支持
	watcher *fsnotify.Watcher
	files   []string
	
	// 重建参数
	bp   *coremain.BP
	args *Args
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	// 返回动态matcher组，支持热重载
	fmt.Printf("[domain_set] GetDomainMatcher调用，返回动态matcher组\n")
	return d.dynamicGroup
}

// rebuildMatcher 重建matcher（简化版）
func (d *DomainSet) rebuildMatcher() error {
	fmt.Printf("[domain_set] 开始重建domain matcher\n")
	
	var matchers []domain.Matcher[struct{}]
	
	// 加载表达式和文件到单个MixMatcher
	if len(d.args.Exps) > 0 || len(d.args.Files) > 0 {
		m := domain.NewDomainMixMatcher()
		if err := LoadExpsAndFiles(d.args.Exps, d.args.Files, m); err != nil {
			fmt.Printf("[domain_set] 加载表达式和文件失败: %v\n", err)
			return err
		}
		if m.Len() > 0 {
			matchers = append(matchers, m)
			fmt.Printf("[domain_set] 成功加载表达式和文件: exps=%d, files=%d, domains=%d\n", 
				len(d.args.Exps), len(d.args.Files), m.Len())
		}
	}
	
	// 添加其他插件的matchers
	for _, tag := range d.args.Sets {
		provider, _ := d.bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			fmt.Printf("[domain_set] 找不到domain matcher provider: %s\n", tag)
			return fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		matcher := provider.GetDomainMatcher()
		matchers = append(matchers, matcher)
		fmt.Printf("[domain_set] 成功添加插件matcher: %s\n", tag)
	}
	
	// 更新动态matcher组
	newGroup := MatcherGroup(matchers)
	d.dynamicGroup.Update(newGroup)
	
	fmt.Printf("[domain_set] domain matcher重建完成，总计%d个matchers\n", len(matchers))
	
	// 打印每个matcher的详细信息
	for i, matcher := range matchers {
		fmt.Printf("[domain_set] matcher[%d]: %T\n", i, matcher)
	}
	
	return nil
}

func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{
		bp:           bp,
		args:         args,
		dynamicGroup: NewDynamicMatcherGroup(),
	}
	
	// 构建初始matcher
	if err := ds.rebuildMatcher(); err != nil {
		return nil, err
	}
	
	// 可选的文件监控
	if args.AutoReload && len(args.Files) > 0 {
		fmt.Printf("[domain_set] 启用文件热重载功能，监控文件: %v\n", args.Files)
		ds.files = args.Files
		if err := ds.startFileWatcher(); err != nil {
			fmt.Printf("[domain_set] 启动文件监控失败: %v\n", err)
			return nil, fmt.Errorf("failed to start file watcher: %w", err)
		}
		fmt.Printf("[domain_set] 文件监控启动成功\n")
	} else {
		fmt.Printf("[domain_set] 文件热重载功能未启用 (auto_reload=%v, files_count=%d)\n", 
			args.AutoReload, len(args.Files))
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

func (d *DomainSet) startFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	
	d.watcher = watcher
	
	for _, file := range d.files {
		if err := watcher.Add(file); err != nil {
			return fmt.Errorf("failed to watch file %s: %w", file, err)
		}
		fmt.Printf("[domain_set] 开始监控文件: %s\n", file)
	}
	
	go d.watchFiles()
	
	return nil
}

func (d *DomainSet) watchFiles() {
	lastReload := time.Now()
	
	fmt.Printf("[domain_set] 文件监控循环开始\n")
	
	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				fmt.Printf("[domain_set] 文件监控事件channel已关闭，退出监控循环\n")
				return
			}
			
			fmt.Printf("[domain_set] 收到文件事件: %s, 操作: %s\n", event.Name, event.Op.String())
			
			if event.Op&fsnotify.Write == fsnotify.Write || 
			   event.Op&fsnotify.Create == fsnotify.Create {
				
				// 检查是否是监控的文件
				monitored := false
				for _, file := range d.files {
					if file == event.Name {
						monitored = true
						break
					}
				}
				
				if !monitored {
					fmt.Printf("[domain_set] 忽略非监控文件的事件: %s\n", event.Name)
					continue
				}
				
				// 简单防抖
				if time.Since(lastReload) < 500*time.Millisecond {
					fmt.Printf("[domain_set] 防抖期内，跳过重载: %s\n", event.Name)
					continue
				}
				
				fmt.Printf("[domain_set] 检测到文件变更，开始热重载: %s\n", event.Name)
				
				// 异步重载，不阻塞
				go func(filename string) {
					start := time.Now()
					if err := d.rebuildMatcher(); err != nil {
						fmt.Printf("[domain_set] 热重载失败 (%s): %v\n", filename, err)
					} else {
						fmt.Printf("[domain_set] 热重载完成 (%s): 耗时 %v\n", filename, time.Since(start))
					}
				}(event.Name)
				
				lastReload = time.Now()
			}
			
		case err, ok := <-d.watcher.Errors:
			if !ok {
				fmt.Printf("[domain_set] 文件监控错误channel已关闭，退出监控循环\n")
				return
			}
			fmt.Printf("[domain_set] 文件监控错误: %v\n", err)
		}
	}
}


func (d *DomainSet) Close() error {
	if d.watcher != nil {
		fmt.Printf("[domain_set] 关闭文件监控器\n")
		return d.watcher.Close()
	}
	return nil
}
