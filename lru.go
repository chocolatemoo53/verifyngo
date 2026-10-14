package main

import (
	"container/list"
	"sync"
)

type lruItem struct {
	key   string
	value interface{}
}

type lruCache struct {
	mu        sync.Mutex
	capacity  int
	items     map[string]*list.Element
	evictList *list.List
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity:  capacity,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
}

func (c *lruCache) Get(key string) interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		return ent.Value.(*lruItem).value
	}
	return nil
}

func (c *lruCache) Put(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		ent.Value.(*lruItem).value = value
		return
	}

	ent := c.evictList.PushFront(&lruItem{key, value})
	c.items[key] = ent

	if c.evictList.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *lruCache) removeOldest() {
	ent := c.evictList.Back()
	if ent != nil {
		c.evictList.Remove(ent)
		kv := ent.Value.(*lruItem)
		delete(c.items, kv.key)
	}
}
