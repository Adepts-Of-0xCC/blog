---
title: "Thoughts on the use of noVNC for phishing campaigns"
date: 2022-09-09 00:00:00 +00:00
modified: 2022-09-09 00:00:00 +00:00
tags: [red team, research, rant, X-C3LL]
description: Detecting NoVNC for phishing campaigns
image: 
---

Dear Fell**owl**ship, today's homily is a rebuke to all those sinners who have decided to abandon the correct path of reverse proxies to bypass 2FA. [Penitenziagite!](https://www.youtube.com/watch?v=gSYPwEsvcpw)

# Prayers at the foot of the Altar a.k.a. disclaimer
*This post will be small and succinct. It should be clear that these are just opinions about this technique that has become trendy in the last weeks, so it will be a much less technical article than we are used to. Thanks for your understanding __:)__*

# Introduction
In recent weeks, we have seen several references to this technique in the context of phishing campaigns, and its possible use to obtain valid sessions by bypassing MFA/2FA. Until now, the preferred technique for intercepting and reusing sessions to evade MFA/2FA has been the use of reverse proxies such as Evilginx or Muraena. These new proof of concepts based on HTML5 VNC clients boil down to the same concept: establishing a Man-in-the-Middle scheme between the victim's browser and the target website, but using a browser in kiosk mode to act as a proxy instead of a server that parses and forwards the requests.

Probably the article that started this new trend was [Steal Credentials & Bypass 2FA Using noVNC](https://mrd0x.com/bypass-2fa-using-novnc/) by [@mrd0x](https://twitter.com/mrd0x).

# Reverse proxy > noVNC
We believe the usage of noVNC and similar technologies is really interesting as proof of concepts, but at the moment they do not reach the bare minimum requirements to be used in real Red Team engagements or even pentesting. Let's take [EvilnoVNC](https://github.com/JoelGMSec/EvilnoVNC) as an example.

While testing this tool the following problems arise:
- Navigation is clunky as hell.
- The URL does not change, always remains the same while browsing.
- The back button breaks the navigation in the "real browser", and not in the one inside the docker.
- Right-click is disabled.
- Links do not show the destination when onmouseover.
- Wrong screen resolution.
- Etc.

Even an untrained user would find out about these issues just with the look and feel.
<figure>
<img src="/NoVNC-phishing/lookfeel.png" alt="Look And Feel">
<figcaption>
Look and feel.
</figcaption>
</figure>

On the other hand, the operator is heavily restricted in order to achieve a minimum of OPSEC. As an example, we can think about the most basic check we should bypass: User-Agent. Mimicking the User-Agent used by the victim is trivial when dealing with proxies, as we only need to forward it in the request from our server to the real website, but in the case of a browser using kiosk mode it is a bit more difficult to achieve. And the same goes for other modifications that we should make to the original request like, for example, blocking the navigation to a `/logout` endpoint that would nuke the session.

Another **fun fact** about this tool is... it does not work. If you test the tool you will find the following:
```
psyconauta@insulanova:/tmp/EvilnoVNC/Downloads|main⚡ ⇒  cat Cookies.txt

        Host: .google.com
        Cookie name: AEC
        Cookie value (decrypted): Encrypted
        Creation datetime (UTC): 2022-09-10 19:44:54.548204
        Last access datetime (UTC): 2022-09-10 21:31:39.833445
        Expires datetime (UTC): 2023-03-09 19:44:54.548204
        ===============================================================

        Host: .google.com
        Cookie name: CONSENT
        Cookie value (decrypted): Encrypted
        Creation datetime (UTC): 2022-09-10 19:44:54.548350
        Last access datetime (UTC): 2022-09-10 21:31:39.833445
        Expires datetime (UTC): 2024-09-09 19:44:54.548350
        ===============================================================
(...)
```

Which is really odd. If you check the code from the [GitHub repo](https://github.com/JoelGMSec/EvilnoVNC/blob/main/Files/cookies.py)...
```python
import os
import json
import base64
import sqlite3
from datetime import datetime, timedelta

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""

def main():
    # local sqlite Chrome cookie database path
    filename = "Downloads/Default/Cookies"
    # connect to the database
    db = sqlite3.connect(filename)
    # ignore decoding errors
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # get the cookies from `cookies` table
    cursor.execute("""
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM cookies""")
    # you can also search by domain, e.g thepythoncode.com
    # cursor.execute("""
    # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    # FROM cookies
    # WHERE host_key like '%thepythoncode.com%'""")
    # get the AES key
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        if not value:
            decrypted_value = "Encrypted"
        else:
            # already decrypted
            decrypted_value = value
        print(f"""
        Host: {host_key}
        Cookie name: {name}
        Cookie value (decrypted): {decrypted_value}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================""")
        # update the cookies table with the decrypted value
        # and make session cookie persistent
        cursor.execute("""
        UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        WHERE host_key = ?
        AND name = ?""", (decrypted_value, host_key, name))
    # commit changes
    db.commit()
    # close connection
    db.close()


if __name__ == "__main__":
    main()
```

As you can see, the script is just a rip off from [this post](https://www.thepythoncode.com/article/extract-chrome-cookies-python), but the author of EvilnoVNC deleted the part where the cookies are decrypted __:facepalm:__.
<figure>
<img src="/NoVNC-phishing/sqlite.jpeg" alt="The cookies that you never will see">
<figcaption>
The cookies that you never will see.
</figcaption>
</figure>

You can not grab the cookies because you are setting its value to the literal string `Encrypted` instead of the real decrypted value __:yet-another-facepalm:__. We did not check if this dockerized version saves the master password in the keyring or if it just uses the hardcoded 'peanuts'. In the former case, copying the files to your profile shouldn't work.

# About detection
The capability to detect this technique heavily relies on what can you inspect. The current published tooling uses a barely modified version of noVNC, meaning that if you are already inspecting web JavaScript to catch malicious stuff like HTML smuggling, you could add signatures to detect the use of RFB. Of course it is trivial to bypass this by simply obfuscating the JavaScript, but you are sure to catch a myriad of ball-busting script kiddies.

```javascript
psyconauta@insulanova:/tmp/EvilnoVNC/Downloads|main⚡ ⇒  curl http://localhost:5980/ 2>&1 | grep RFB
        // RFB holds the API to connect and communicate with a VNC server
        import RFB from './core/rfb.js';
        // Creating a new RFB object will start a new connection
        rfb = new RFB(document.getElementById('screen'), url,
        // Add listeners to important events from the RFB module
```

Moreover, all control is done through the RFB over WebSockets protocol, so it is quite easy to spot this type of traffic as it is unencrypted at the application level.
<figure>
<img src="/NoVNC-phishing/rfb.jpeg" alt="RFB traffic in clear being send through WebSockets (ws:yourdomain/websockify)">
<figcaption>
RFB traffic being sent through WebSockets (ws:yourdomain/websockify).
</figcaption>
</figure>

Additionally, because this protocol is easy to implement, you can create a small script to send keystrokes and/or mouse movements directly to escape from Chromium to the desktop.
<figure>
<img src="/NoVNC-phishing/jailbreak.jpeg" alt="Jailbreak">
<figcaption>
Jailbreaking chromium.
</figcaption>
</figure>

This tool executes noVNC on a docker so there is not much to do after escaping from Chromium, but think about other script kiddies who execute it directly on a server __:)__. Automating the scanner & pwnage of this kind of phishing sites is easy if you have the time.

From the point of view of the endpoint to log into, it is easier to detect the use of a User-Agent other than the usual one. If your user base accesses your VPN web portal from Windows, someone connecting from Linux should trigger an alert.

And finally, the classic "training-education-whatever" of users would help a lot as the current state of the art is trivial to spot.

# EoF
Tooling around this concept of MFA/2FA bypassing is still too rudimentary to be used in real engagements, although they are really cool proof of concepts. We believe it will evolve within the next years (or months) and people will start to work on better approaches. For now, reverse proxies are still more powerful as they can be easily configured to blend in with legitimate traffic, and the user does not experience look and feel annoyances.

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).
