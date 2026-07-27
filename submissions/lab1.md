# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Windowns/ Ubuntu 24.04>
- Docker version: Docker version 29.1.3, build f52814d  

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: no (default)

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
[{ 
"id": 1,
 "name": "Apple Juice (1000ml)", 
 "description": "The all-time classic.", 
 "price": 1.99, 
"deluxePrice": 0.99, 
"image": "apple_juice.jpg", 
 "createdAt": "2026-07
- Container uptime: 
CONTAINER ID   IMAGE                           COMMAND                  CREATED          STATUS          PORTS                      NAMES
a20fb3e3303c   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   16 minutes ago   Up 16 minutes   127.0.0.1:3000->3000/tcp   juice-shop

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: visible in top-right Account menu
- Product listing/search present: [x] Yes [ ] No — notes: 
- Admin or account area discoverable: [ ] Yes [x] No — notes: 
- Client-side errors in DevTools console: [ ] Yes [x] No
- Pre-populated local storage / cookies: none observed

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                                                          
								Dload  Upload   Total   Spent    Left  Speed                                             
	0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0                                          
	HTTP/1.1 200 OK                                                                                                         
	Access-Control-Allow-Origin: *                                                                                          
	X-Content-Type-Options: nosniff                                                                                         
	X-Frame-Options: SAMEORIGIN                                                                                             
	Feature-Policy: payment 'self'                                                                                          
	X-Recruiting: /#/jobs                                                                                                  
	Accept-Ranges: bytes                                                                                                    
	Cache-Control: public, max-age=0                                                                                        
	Last-Modified: Mon, 27 Jul 2026 13:30:16 GMT                                                                            
	ETag: W/"26af-19fa3c4dfdc"                                                                                              
	Content-Type: text/html; charset=UTF-8                                                                                  
	Content-Length: 9903                                                                                                    
	Vary: Accept-Encoding                                                                                                   
	Date: Mon, 27 Jul 2026 13:52:49 GMT                                                                                     
	Connection: keep-alive                                                                                                  
	Keep-Alive: timeout=5   
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [x] `X-Content-Type-Options: nosniff`
- [x] `X-Frame-Options`
## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: 3 items (title, no secrets, submission file)
- Auto-fill verified: [ ] Yes — opened draft PR and template appeared