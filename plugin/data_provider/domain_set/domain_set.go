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
	"sync"

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

// 初始化插件
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
	mg      []domain.Matcher[struct{}]
	watcher *fsnotify.Watcher
	files   []string
	mx      sync.RWMutex
	bp      *coremain.BP
	args    *Args
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	d.mx.RLock()
	defer d.mx.RUnlock()
	return MatcherGroup(d.mg)
}

// NewDomainSet inits a DomainSet from given args.
func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{
		bp:   bp,
		args: args,
	}

	m := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles(args.Exps, args.Files, m); err != nil {
		return nil, err
	}
	if m.Len() > 0 {
		ds.mg = append(ds.mg, m)
	}

	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		matcher := provider.GetDomainMatcher()
		ds.mg = append(ds.mg, matcher)
	}

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
	}
	
	// 启动监控goroutine
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
			
			// 只处理写入和创建事件
			if event.Op&fsnotify.Write == fsnotify.Write || 
			   event.Op&fsnotify.Create == fsnotify.Create {
				d.reloadFiles()
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

// reloadFiles 重新加载所有文件
func (d *DomainSet) reloadFiles() {
	d.mx.Lock()
	defer d.mx.Unlock()
	
	// 创建新的matcher
	newMatchers := make([]domain.Matcher[struct{}], 0, len(d.args.Sets)+1)
	
	// 重新加载文件数据
	m := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles(d.args.Exps, d.args.Files, m); err != nil {
		return // 静默失败，保持当前状态
	}
	if m.Len() > 0 {
		newMatchers = append(newMatchers, m)
	}
	
	// 重新添加其他插件提供的matcher
	for _, tag := range d.args.Sets {
		provider, _ := d.bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			continue
		}
		matcher := provider.GetDomainMatcher()
		newMatchers = append(newMatchers, matcher)
	}
	
	// 原子性更新匹配器列表
	d.mg = newMatchers
}

// Close 关闭文件监控器
func (d *DomainSet) Close() error {
	if d.watcher != nil {
		return d.watcher.Close()
	}
	return nil
}
