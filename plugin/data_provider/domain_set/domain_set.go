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
	"sync/atomic"
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
	fileMatchers map[string]domain.Matcher[struct{}]
	setMatchers  []domain.Matcher[struct{}]
	expMatcher   domain.Matcher[struct{}]
	
	cachedMatcher atomic.Value
	
	watcher *fsnotify.Watcher
	files   []string
	mx      sync.RWMutex
	bp      *coremain.BP
	args    *Args
	
	lastReloadTime map[string]time.Time
	reloadMutex    sync.Mutex
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	if cached := d.cachedMatcher.Load(); cached != nil {
		return cached.(MatcherGroup)
	}
	
	d.rebuildCache()
	
	if cached := d.cachedMatcher.Load(); cached != nil {
		return cached.(MatcherGroup)
	}
	
	return MatcherGroup{}
}

func (d *DomainSet) rebuildCache() {
	d.mx.RLock()
	defer d.mx.RUnlock()
	d.rebuildCacheUnsafe()
}

func (d *DomainSet) rebuildCacheUnsafe() {
	capacity := len(d.fileMatchers) + len(d.setMatchers)
	if d.expMatcher != nil {
		capacity++
	}
	allMatchers := make([]domain.Matcher[struct{}], 0, capacity)
	
	if d.expMatcher != nil {
		allMatchers = append(allMatchers, d.expMatcher)
	}
	
	for _, matcher := range d.fileMatchers {
		if matcher != nil {
			allMatchers = append(allMatchers, matcher)
		}
	}
	
	allMatchers = append(allMatchers, d.setMatchers...)
	
	newMatcherGroup := MatcherGroup(allMatchers)
	d.cachedMatcher.Store(newMatcherGroup)
}

func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{
		bp:             bp,
		args:           args,
		fileMatchers:   make(map[string]domain.Matcher[struct{}]),
		lastReloadTime: make(map[string]time.Time),
	}

	if len(args.Exps) > 0 {
		expMatcher := domain.NewDomainMixMatcher()
		if err := LoadExps(args.Exps, expMatcher); err != nil {
			return nil, err
		}
		ds.expMatcher = expMatcher
	}

	for _, file := range args.Files {
		fileMatcher := domain.NewDomainMixMatcher()
		if err := LoadFile(file, fileMatcher); err != nil {
			return nil, fmt.Errorf("failed to load file %s: %w", file, err)
		}
		ds.fileMatchers[file] = fileMatcher
	}

	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		matcher := provider.GetDomainMatcher()
		ds.setMatchers = append(ds.setMatchers, matcher)
	}

	ds.rebuildCache()

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
	}
	
	go d.watchFiles()
	
	return nil
}

func (d *DomainSet) watchFiles() {
	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}
			
			if event.Op&fsnotify.Write == fsnotify.Write || 
			   event.Op&fsnotify.Create == fsnotify.Create {
				d.reloadSingleFile(event.Name)
			}
			
		case err, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
			_ = err
		}
	}
}

func (d *DomainSet) reloadSingleFile(filePath string) {
	d.reloadMutex.Lock()
	now := time.Now()
	lastTime, exists := d.lastReloadTime[filePath]
	
	debounceInterval := 500 * time.Millisecond
	if exists && now.Sub(lastTime) < debounceInterval {
		d.reloadMutex.Unlock()
		return
	}
	
	d.lastReloadTime[filePath] = now
	d.reloadMutex.Unlock()
	
	d.mx.Lock()
	defer d.mx.Unlock()
	
	if _, monitored := d.fileMatchers[filePath]; !monitored {
		return
	}
		
	newFileMatcher := domain.NewDomainMixMatcher()
	if err := LoadFile(filePath, newFileMatcher); err != nil {
		return
	}
	
	d.fileMatchers[filePath] = newFileMatcher
	d.rebuildCacheUnsafe()
}

func (d *DomainSet) reloadFiles() {
	d.mx.Lock()
	defer d.mx.Unlock()
	
	if len(d.args.Exps) > 0 {
		expMatcher := domain.NewDomainMixMatcher()
		if err := LoadExps(d.args.Exps, expMatcher); err == nil {
			d.expMatcher = expMatcher
		}
	}
	
	for _, file := range d.args.Files {
		fileMatcher := domain.NewDomainMixMatcher()
		if err := LoadFile(file, fileMatcher); err == nil {
			d.fileMatchers[file] = fileMatcher
		}
	}
	
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

func (d *DomainSet) Close() error {
	if d.watcher != nil {
		return d.watcher.Close()
	}
	return nil
}
