# Kompilasi untuk Linux/Mac
go build -o haqtivist haqtivist.go

# Kompilasi untuk Windows
go build -o haqtivist.exe haqtivist.go

# Testing website sendiri
./haqtivist -target http://localhost:8080 -threads 50 -duration 30

# Testing dengan POST data
./haqtivist -target https://yoursite.com/api -method POST -data "key=value" -threads 100

# Testing dengan random IP spoofing
./haqtivist -target https://yoursite.com -random-ip -threads 200

# Testing dengan custom headers
./haqtivist -target https://yoursite.com -header "X-Custom: value" -header "Authorization: Bearer token"

# Testing dengan delay (menghindari detection)
./haqtivist -target https://yoursite.com -delay 100 -threads 50

# Verbose mode untuk debugging
./haqtivist -target https://yoursite.com -verbose -duration 60

Contoh Output:

```
╔══════════════════════════════════════════════════════════════════╗
║              Web Stress Testing Tool - Legal Use Only            ║
╚══════════════════════════════════════════════════════════════════╝

Version: 1.0.0

🚀 Starting stress test...
======================================================================

📊 Test Configuration:
   Target: https://yoursite.com
   Method: GET
   Threads: 50
   Safe Mode: false
   Random IP: true
   Delay: 0ms

Active | Requests | Success | Errors | Status
-------|----------|---------|--------|-------
   50  |     1000 |     998 |      2 | Running

======================================================================
📊 FINAL TEST STATISTICS
======================================================================

⏱️  Test Duration:     30.45 seconds
📨 Total Requests:    1523
✅ Successful:        1518
❌ Errors:            5
📈 Success Rate:      99.67%
📊 Requests/Second:   50.02

⏱️  Response Time Stats:
   Average: 245ms
   Minimum: 89ms
   Maximum: 1234ms

📋 Assessment:
   ✅ Server handled the load well
```
