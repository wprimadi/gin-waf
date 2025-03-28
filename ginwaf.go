// Package ginwaf provides a Web Application Firewall (WAF) middleware for the Gin framework.
// It offers protection against malicious requests by blocking suspicious patterns,
// enforcing rate limits, and filtering requests based on IPs and User-Agents.
//
// Author: Wahyu Primadi
// Email: saya@wahyuprimadi.com
// Website: https://wahyuprimadi.com
//
// Usage:
//
//	r := gin.Default()
//	wafConfig := ginwaf.WAFConfig{
//	    BlockedIPs:        map[string]bool{"192.168.1.1": true},
//	    WhitelistedIPs:    map[string]bool{"127.0.0.1": true},
//	    RateLimit:         100,
//	    RateWindow:        time.Minute,
//	    BlockedUserAgents: []string{"malicious-bot"},
//	}
//	r.Use(ginwaf.GinWAF(wafConfig))
//	r.Run()
//
// This middleware helps protect your Gin-based applications from various security threats.
package ginwaf

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type WAFConfig struct {
	BlockedIPs        map[string]bool
	WhitelistedIPs    map[string]bool
	RateLimit         int           // Requests per minute
	RateWindow        time.Duration // Window for rate limiting
	BlockedUserAgents []string
}

type rateLimiter struct {
	requests sync.Map
}

type TrieNode struct {
	children map[rune]*TrieNode
	isEnd    bool
}

type Trie struct {
	root *TrieNode
}

func NewTrie() *Trie {
	return &Trie{root: &TrieNode{children: make(map[rune]*TrieNode)}}
}

func (t *Trie) Insert(word string) {
	node := t.root
	for _, char := range word {
		if _, exists := node.children[char]; !exists {
			node.children[char] = &TrieNode{children: make(map[rune]*TrieNode)}
		}
		node = node.children[char]
	}
	node.isEnd = true
}

func (t *Trie) Search(word string) bool {
	node := t.root
	for _, char := range word {
		if _, exists := node.children[char]; !exists {
			return false
		}
		node = node.children[char]
	}
	return node.isEnd
}

var blockedTrie = NewTrie()
var blockedPatterns = []string{
	"select from",
	"union select",
	"insert into",
	"delete from",
	"update set",
	"drop table",
	"shutdown",
	"xp_cmdshell",
	"<script>",
	"onerror",
	"javascript:",
	"x22",
	"{|}|{",
	"mb_ereg_replace",
	"file_put_contents",
	"\\?input=<script>",
	"1=1",
	"=",
}

func init() {
	for _, pattern := range blockedPatterns {
		blockedTrie.Insert(pattern)
	}
}

func GinWAF(config WAFConfig) gin.HandlerFunc {
	limiter := &rateLimiter{}

	// Background goroutine to reset request counts
	go func() {
		ticker := time.NewTicker(config.RateWindow)
		defer ticker.Stop()
		for range ticker.C {
			limiter.requests.Range(func(key, _ interface{}) bool {
				limiter.requests.Delete(key)
				return true
			})
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		decodedQuery, _ := url.QueryUnescape(query)
		userAgent := c.GetHeader("User-Agent")

		// Allow whitelisted IPs
		if config.WhitelistedIPs[ip] {
			c.Next()
			return
		}

		// Check blocked IPs
		if config.BlockedIPs[ip] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}

		// Check blocked User-Agents
		for _, blockedUA := range config.BlockedUserAgents {
			if userAgent == blockedUA {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden User-Agent"})
				return
			}
		}

		// Check blocked patterns in path and query parameters
		if blockedTrie.Search(path) || blockedTrie.Search(query) || blockedTrie.Search(decodedQuery) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Malicious request detected"})
			return
		}

		// Check blocked patterns in request body
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			buf := make([]byte, 1024)
			n, _ := c.Request.Body.Read(buf)
			body := string(buf[:n])
			if blockedTrie.Search(body) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Malicious request detected in body"})
				return
			}
		}

		// Rate limiting
		if config.RateLimit > 0 {
			count, _ := limiter.requests.LoadOrStore(ip, 0)
			currentCount := count.(int) + 1
			limiter.requests.Store(ip, currentCount)

			if currentCount > config.RateLimit {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
				return
			}
		}

		c.Next()
	}
}
