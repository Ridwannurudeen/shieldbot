# DNS Configuration for shieldbotsecurity.online

## Required DNS Records

`<CURRENT_VPS_PUBLIC_IPV4>` is a placeholder, not an address. Get the current public IPv4
from the VPS provider's console for the server you intend to configure; do not reuse a
historical address from this repository.

Log in to your domain registrar's DNS management panel and add these records:

### A Record (Required)
```
Type: A
Name: api
Value: <CURRENT_VPS_PUBLIC_IPV4>
TTL: 300 (or Auto)
```

This creates: `api.shieldbotsecurity.online` → `<CURRENT_VPS_PUBLIC_IPV4>`

### Optional: Root Domain
```
Type: A
Name: @ (or leave blank)
Value: <CURRENT_VPS_PUBLIC_IPV4>
TTL: 300
```

This creates: `shieldbotsecurity.online` → `<CURRENT_VPS_PUBLIC_IPV4>`

## Verification

After adding the DNS records, wait 5-10 minutes for propagation, then test:

```bash
# Test DNS resolution
nslookup api.shieldbotsecurity.online

# Should return:
# Name: api.shieldbotsecurity.online
# Address: <CURRENT_VPS_PUBLIC_IPV4>
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
3. Type: A, Name: api, IPv4: <CURRENT_VPS_PUBLIC_IPV4>
4. **Important:** Set Proxy status to "DNS only" (gray cloud, not orange)

**GoDaddy:**
1. My Products → DNS → Manage Zones
2. Click "Add"
3. Type: A, Name: api, Value: <CURRENT_VPS_PUBLIC_IPV4>

**Porkbun:**
1. Account → Domain Management → DNS
2. Quick DNS Config → Add → A
3. Host: api, Answer: <CURRENT_VPS_PUBLIC_IPV4>

## Next Steps

Once DNS is configured:
1. Wait 5-10 minutes for propagation
2. Test: `ping api.shieldbotsecurity.online`
3. Should return: `<CURRENT_VPS_PUBLIC_IPV4>`
4. Proceed to Caddy installation

Both setup scripts require `VPS_IP` in the environment and stop if it is unset or empty.
Replace the placeholder before running either script on the intended server:

```bash
export VPS_IP='<CURRENT_VPS_PUBLIC_IPV4>'
# Choose the setup script for your server:
bash deploy/setup-bare-domain.sh  # nginx
# or: bash deploy/setup-https.sh  # Caddy
```
