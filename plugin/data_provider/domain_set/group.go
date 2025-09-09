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
	"sync/atomic"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

type MatcherGroup []domain.Matcher[struct{}]

func (mg MatcherGroup) Match(s string) (struct{}, bool) {
	for _, m := range mg {
		if _, ok := m.Match(s); ok {
			return struct{}{}, true
		}
	}
	return struct{}{}, false
}

// DynamicMatcherGroup 动态matcher组，支持热重载
type DynamicMatcherGroup struct {
	matchers *atomic.Value  // 存储MatcherGroup
}

func NewDynamicMatcherGroup() *DynamicMatcherGroup {
	dmg := &DynamicMatcherGroup{
		matchers: &atomic.Value{},
	}
	// 初始化为空组
	dmg.matchers.Store(MatcherGroup{})
	return dmg
}

func (dmg *DynamicMatcherGroup) Update(mg MatcherGroup) {
	dmg.matchers.Store(mg)
}

func (dmg *DynamicMatcherGroup) Match(s string) (struct{}, bool) {
	mg := dmg.matchers.Load().(MatcherGroup)
	return mg.Match(s)
}
