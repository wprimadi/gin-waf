# GinWAF - Web Application Firewall Middleware for Gin

GinWAF is a Web Application Firewall (WAF) middleware for the Gin web framework. It helps protect your application from malicious requests by blocking suspicious patterns, enforcing rate limits, and filtering requests based on IP addresses and User-Agent headers.

## Features
- **IP Filtering**: Blocklist and allowlist support for IP addresses.
- **Rate Limiting**: Configurable request rate limit per IP.
- **User-Agent Filtering**: Block requests from known malicious bots and crawlers.
- **Pattern Matching**: Blocks suspicious request patterns to mitigate SQL injection, XSS, and other attacks.
- **Trie-based Pattern Matching**: Efficient request pattern detection using a Trie data structure.

## Installation
```sh
go get github.com/wprimadi/gin-waf
```

## Usage

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/wprimadi/gin-waf"
	"time"
)

func main() {
	r := gin.Default()

	wafConfig := ginwaf.WAFConfig{
		BlockedIPs:        map[string]bool{"192.168.1.1": true},
		WhitelistedIPs:    map[string]bool{"127.0.0.1": true},
		RateLimit:         100,
		RateWindow:        time.Minute,
		BlockedUserAgents: []string{"malicious-bot"},
	}

	r.Use(ginwaf.GinWAF(wafConfig))

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Welcome to GinWAF-protected API!"})
	})

	r.Run()
}
```

## Configuration
- **BlockedIPs**: A map of blocked IPs.
- **WhitelistedIPs**: A map of allowed IPs that bypass WAF.
- **RateLimit**: Maximum number of requests allowed per IP in the specified time window.
- **RateWindow**: Duration for rate limit enforcement.
- **BlockedUserAgents**: A list of User-Agent strings to be blocked.

## License
This project is open-source and available under the MIT License.

## Author
**Wahyu Primadi**  
Email: [saya@wahyuprimadi.com](mailto:saya@wahyuprimadi.com)  
Website: [https://wahyuprimadi.com](https://wahyuprimadi.com)

