# DNS Configuration for shieldbotsecurity.online

## Required DNS Records

Log in to your domain registrar's DNS management panel and add these records:

### A Record (Required)
```
Type: A
Name: api
Value: 38.49.212.108
TTL: 300 (or Auto)
```

This creates: `api.shieldbotsecurity.online` → `38.49.212.108`

### Optional: Root Domain
```
Type: A
Name: @ (or leave blank)
Value: 38.49.212.108
TTL: 300
```

This creates: `shieldbotsecurity.online` → `38.49.212.108`

## Verification

After adding the DNS records, wait 5-10 minutes for propagation, then test:

```bash
# Test DNS resolution
nslookup api.shieldbotsecurity.online

# Should return:
# Name: api.shieldbotsecurity.online
# Address: 38.49.212.108
```

Or use online tools:
- https://dnschecker.org - Check global DNS propagation
- https://mxtoolbox.com/DNSLookup.aspx - DNS lookup tool

## Common Registrars - Where to Add Records

**Namecheap:**
1. Dashboard → Manage → Advanced DNS
2. Click "Add New Record"
3. Select "A Record"
4. Enter values above

**Cloudflare:**
1. Dashboard → DNS → Records
2. Click "Add record"
3. Type: A, Name: api, IPv4: 38.49.212.108
4. **Important:** Set Proxy status to "DNS only" (gray cloud, not orange)

**GoDaddy:**
1. My Products → DNS → Manage Zones
2. Click "Add"
3. Type: A, Name: api, Value: 38.49.212.108

**Porkbun:**
1. Account → Domain Management → DNS
2. Quick DNS Config → Add → A
3. Host: api, Answer: 38.49.212.108

## Next Steps

Once DNS is configured:
1. Wait 5-10 minutes for propagation
2. Test: `ping api.shieldbotsecurity.online`
3. Should return: `38.49.212.108`
4. Proceed to Caddy installation
