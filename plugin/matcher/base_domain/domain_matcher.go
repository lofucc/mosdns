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

package base_domain

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"strings"
)

var _ sequence.Matcher = (*Matcher)(nil)

type Args struct {
	Exps       []string `yaml:"exps"`
	DomainSets []string `yaml:"domain_sets"`
	Files      []string `yaml:"files"`
}

type MatchFunc func(qCtx *query_context.Context, m domain.Matcher[struct{}]) (bool, error)

type Matcher struct {
	match     MatchFunc
	mg        []domain.Matcher[struct{}]
	providers []data_provider.DomainMatcherProvider
	bq        sequence.BQ
}

func (m *Matcher) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	// 预分配切片避免多次扩容
	dynamicMatchers := make([]domain.Matcher[struct{}], 0, len(m.providers)+len(m.mg))
	
	// 从providers获取最新的matchers
	for _, provider := range m.providers {
		dm := provider.GetDomainMatcher()
		dynamicMatchers = append(dynamicMatchers, dm)
	}
	
	// 添加静态的匿名matchers
	dynamicMatchers = append(dynamicMatchers, m.mg...)
	
	return m.match(qCtx, domain_set.MatcherGroup(dynamicMatchers))
}

func NewMatcher(bq sequence.BQ, args *Args, f MatchFunc) (m *Matcher, err error) {
	m = &Matcher{
		match: f,
		bq:    bq,
	}

	// 存储providers以便动态获取最新的matchers
	for _, tag := range args.DomainSets {
		p := bq.M().GetPlugin(tag)
		dsProvider, _ := p.(data_provider.DomainMatcherProvider)
		if dsProvider == nil {
			return nil, fmt.Errorf("cannot find domain set %s", tag)
		}
		m.providers = append(m.providers, dsProvider)
	}

	// Anonymous set from plugin's args and files.
	if len(args.Exps)+len(args.Files) > 0 {
		anonymousSet := domain.NewDomainMixMatcher()
		if err := domain_set.LoadExpsAndFiles(args.Exps, args.Files, anonymousSet); err != nil {
			return nil, err
		}
		if anonymousSet.Len() > 0 {
			m.mg = append(m.mg, anonymousSet)
		}
	}

	return m, nil
}

// ParseQuickSetupArgs parses expressions and domain set to args.
// Format: "([exp] | [$domain_set_tag] | [&domain_list_file])..."
func ParseQuickSetupArgs(s string) *Args {
	cutPrefix := func(s string, p string) (string, bool) {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p), true
		}
		return s, false
	}

	args := new(Args)
	for _, exp := range strings.Fields(s) {
		if tag, ok := cutPrefix(exp, "$"); ok {
			args.DomainSets = append(args.DomainSets, tag)
		} else if path, ok := cutPrefix(exp, "&"); ok {
			args.Files = append(args.Files, path)
		} else {
			args.Exps = append(args.Exps, exp)
		}
	}
	return args
}
