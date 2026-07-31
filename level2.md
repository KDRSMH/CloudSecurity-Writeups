# flaws.cloud — Level 2

## 1. Özet

Level 1'den farklı olarak bu seviyede bucket, **AllUsers** (anonim/herkes)
grubuna değil, **AuthenticatedUsers** grubuna okuma/listeleme izni veriyor.
Bu, S3'e özgü, sık yanlış anlaşılan bir kavram: `AuthenticatedUsers` grubu
"benim uygulamamın kayıtlı kullanıcıları" ya da "kendi AWS hesabım"
anlamına gelmez — **AWS'te herhangi bir hesapla imzalı (signed) istek
gönderen herkes** anlamına gelir. Yani bucket sahibinin tanımadığı, hiç
ilişkisi olmayan üçüncü bir AWS müşterisi bile, kendi ücretsiz (free tier)
AWS hesabıyla imzalı bir istek göndererek bucket'ı listeleyebilir.

Sonuç olarak:
- **Anonim istek** (kimlik doğrulamasız) → reddedilir (403).
- **İmzalı istek** (herhangi bir geçerli AWS hesabıyla, `--no-sign-request`
  kullanılmadan) → kabul edilir.

Bu, admin tarafında sık görülen bir yanılgının sömürüsü: "authenticated"
kelimesini "benim IAM kullanıcılarım/organizasyonum" olarak okumak, halbuki
S3 ACL'lerinde bu grup **tüm AWS ekosistemini** kapsıyor.

## 2. Sömürü (Exploit)

Level 1'in aksine bu bucket'ta doğrudan `--no-sign-request` ile anonim
listeleme çalışmıyor (flaws.cloud'un kendi açıklamasında da Level 2 girişi
"you're going to need your own AWS account for this" diyerek bu twist'e
işaret ediyor — bkz. aşağıdaki referans görsel). İlk denemede, henüz
tanımlanmamış bir profil adıyla (`AKIASRHGIRYYD4IULUUQ` — bir access key ID
gibi görünen ama `--profile` parametresine profil adı olarak verilen bir
değer) komut çalıştırıldı ve bu bir AWS CLI yapılandırma hatasıyla
sonuçlandı (S3 iznine ilişkin bir yanıt değil):

```bash
aws s3 --profile AKIASRHGIRYYD4IULUUQ ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
```

```
aws: [ERROR]: The config profile (AKIASRHGIRYYD4IULUUQ) could not be found
```

Ardından `--no-sign-request` **kullanılmadan**, yani AWS CLI'nin varsayılan
(kadir'in kendi, imzalı) kimlik bilgileriyle aynı komut tekrar çalıştırıldı
ve bucket başarıyla listelendi:

```bash
aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud --region us-west-2
```

Çıktı (sömürülen izin: bucket ACL'inde `AuthenticatedUsers` grubuna
tanınmış `READ`/list izni):

```
2017-02-27 05:02:15       80751 everyone.png
2017-03-03 06:47:17        1433 hint1.html
2017-02-27 05:04:39        1035 hint2.html
2017-02-27 05:02:14        2786 index.html
2017-02-27 05:02:14          26 robots.txt
2017-02-27 05:02:15        1051 secret-e4443fc.html
```

![Profil hatası veren ilk deneme ve ardından imzalı (kadir'in kendi AWS hesabıyla) aws s3 ls komutunun bucket içeriğini listelemesi](/screenshots/level*2cliekomut.png)

Listede yine normalden farklı bir `secret-e4443fc.html` dosyası var. Bu
dosya `curl` ile çekildiğinde flAWS ASCII banner'ı, "Congrats! You found the
secret file!" mesajı ve Level 3 adresi ortaya çıktı:

```bash
curl -s http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/secret-e4443fc.html
```

> Congrats! You found the secret file!
> Level 3 is at `http://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud`

![secret-e4443fc.html sayfasının curl çıktısı — Congrats mesajı ve Level 3 adresi](/screenshots/level*2.png)

Referans olarak, flaws.cloud'un kendi Level 1 açıklaması "Everyone" ACL
grantının ("List" izni verilmiş) "anyone on the Internet" (internetteki
herkes) anlamına geldiğini vurguluyor ve Level 2 girişinde "kendi AWS
hesabınıza ihtiyacınız olacak" diyerek bu seviyenin artık anonim değil,
imzalı bir AWS kimliği gerektirdiğine işaret ediyor:

![flaws.cloud'un kendi sayfasından: Level 1'deki "Everyone" ACL hatasının açıklaması ve Level 2 girişinde "kendi AWS hesabına ihtiyacın olacak" notu](/screenshots/level-2fark.png)

**Level 1 ile fark:**

| | Level 1 | Level 2 |
|---|---|---|
| Sömürülen grant | `AllUsers` (herkese açık grup) | `AuthenticatedUsers` (herhangi bir AWS hesabı grubu) |
| Gerekli kimlik | Yok — `--no-sign-request` yeterli | Herhangi bir geçerli, imzalı AWS hesabı |
| Kim erişebilir | Tüm internet, hesapsız | Tüm internet, ama **bir AWS hesabı olmak şartıyla** (kendi ücretsiz hesabınız dahil) |

## 3. Önleme (Remediation) — Kendi Test Ortamımda (`test-lab-level1`)

### a) Açığı yeniden üretme (ground-truth)

Aynı ACL grubu, `test-lab-level1` bucket'ıma `--grant-read` ile tanındı ve
ardından imzalı (kendi hesabımla, `--no-sign-request` kullanmadan) listeleme
denendi:

```bash
aws s3api put-bucket-acl \
  --bucket test-lab-level1 \
  --grant-read uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers \
  --region us-west-2

aws s3 ls s3://test-lab-level1/ --region us-west-2
```

```
2026-07-28 23:59:16          17 test.txt
```

Bu, `flaws.cloud`'daki zafiyetin kendi ortamımda birebir kanıtı: grant
sadece "kendi hesabım" ile değil, herhangi bir imzalı AWS isteğiyle
çalışıyor — çünkü grantee bir kullanıcı/hesap ID'si değil, `AuthenticatedUsers`
**önceden tanımlı grup URI'si**.

![put-bucket-acl ile AuthenticatedUsers grubuna read izni verilmesi ve ardından imzalı aws s3 ls ile test.txt dosyasının listelenmesi](/screenshots/önleme%20level-2.png)

### b) Önlem: grant'in kaldırılması

Grant, `--acl private` ile kaldırıldı; `get-bucket-acl` çıktısı artık sadece
bucket sahibinin `FULL_CONTROL` yetkisini gösteriyor, `AuthenticatedUsers`
girişi tamamen kayboldu:

```bash
aws s3api put-bucket-acl --bucket test-lab-level1 --acl private --region us-west-2
aws s3api get-bucket-acl --bucket test-lab-level1 --region us-west-2
```

```json
{
    "Owner": {
        "ID": "06aa63bfb553cc06617d260da81f48893a4fca6bd2a45e4f9ea3331f6159df39"
    },
    "Grants": [
        {
            "Grantee": {
                "ID": "06aa63bfb553cc06617d260da81f48893a4fca6bd2a45e4f9ea3331f6159df39",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}
```

![put-bucket-acl --acl private sonrası get-bucket-acl çıktısı — sadece owner FULL_CONTROL kaldı, AuthenticatedUsers grant'i yok](/screenshots/level-2kanıts.png)

### c) Defense-in-depth (yazılı öneri)

Tek tek grant kaldırmak reaktif bir çözüm; kalıcı ve tekrar oluşmasını
engelleyen iki katmanlı bir savunma öneriyorum:

1. **Object Ownership → "Bucket owner enforced" (ACLs disabled).** Level
   1'in önleme bölümünde uyguladığım bu ayar, ACL mekanizmasının tamamını
   devre dışı bırakır. ACL'ler kapalıyken `put-bucket-acl` ile
   `AuthenticatedUsers` (ya da `AllUsers`) grubuna bir daha grant verilemez;
   erişim yalnızca bucket policy/IAM üzerinden, bilinçli ve incelenebilir
   şekilde tanımlanabilir. Bu, hem Level 1 hem Level 2 sınıfı hataları aynı
   anda kapatır.
2. **S3 Block Public Access'in dört ayarının açık tutulması.** AWS, Block
   Public Access kapsamında "public" tanımını sadece `AllUsers` ile
   sınırlamaz; **`AuthenticatedUsers` grubuna verilen ACL grant'lerini de
   "public" olarak sınıflandırır.** Yani Level 1 remediation'ında
   `test-lab-level1` üzerinde açtığım `BlockPublicAcls`/`RestrictPublicBuckets`
   ayarları etkinken kalsaydı, bu bölümdeki `AuthenticatedUsers` grant
   denemesi de en baştan `AccessDenied` ile reddedilirdi — tıpkı Level 1'in
   `public-read` ACL denemesinin reddedildiği gibi. Dolayısıyla Block Public
   Access, Object Ownership ayarından bağımsız olarak ikinci bir güvenlik
   katmanı sağlıyor.

## 4. Tespit (Detection)

Level 1'deki CloudTrail imzasından temel fark, isteğin artık **anonim
değil, gerçek bir AWS kimliğiyle** gelmesi:

- **`userIdentity` alanı `ANONYMOUS_PRINCIPAL` değil.** `ListObjects`/
  `ListObjectsV2` olayında `userIdentity.type` genellikle `AWSAccount` veya
  `IAMUser`, `userIdentity.accountId` ise **gerçek, geçerli bir 12 haneli
  AWS hesap numarası** olarak görünür. Sorun şu ki bu `accountId`,
  savunan tarafın kendi organizasyonuna (AWS Organizations'daki bilinen
  hesap listesine) ait değildir.
- **Sinyal — "yabancı hesap" (foreign principal) erişimi**: Log
  izlemesinde en anlamlı kontrol, `userIdentity.accountId` değerinin
  şirketin bilinen/beyaz listedeki hesap ID'leri kümesinde olup olmadığını
  kontrol etmektir. Kendi organizasyon hesapları dışından gelen herhangi
  bir `s3:ListBucket`/`GetObject` çağrısı, ACL veya bucket policy üzerinden
  istenmeyen bir cross-account grant olduğuna işaret eder.
- **IAM Access Analyzer**: Bu senaryo için özellikle isabetli bir kontrol —
  Access Analyzer, bir S3 bucket'ının ACL veya bucket policy yoluyla
  **hesap dışı (external) bir principal'a** (ki `AuthenticatedUsers` grubu
  tanım gereği "her hesap" olduğundan bunu external erişim olarak
  raporlar) erişim verdiğini otomatik olarak bulur ve "harici erişim"
  bulgusu üretir — saldırı gerçekleşmeden önce yapılandırma hatasını
  yakalar.
- **GuardDuty**: S3 Protection etkinse, bilinmeyen/ilk kez görülen bir AWS
  hesabından gelen erişim desenlerini anomalili S3 veri olayı olarak
  işaretleyebilir; ancak Level 1'deki `Policy:S3/BucketAnonymousAccessGranted`
  kadar isim bazlı özel bir bulgu tipi olmadığından, bu senaryoda birincil
  tespit katmanı IAM Access Analyzer + CloudTrail `accountId` beyaz
  listesi kontrolüdür.

## 5. Kendi Test Ortamı Kanıtı — `test-lab-level1` Ground-Truth Özeti

| Adım | Komut | Sonuç |
|---|---|---|
| Grant verme | `put-bucket-acl --grant-read uri=.../AuthenticatedUsers` | Grant başarıyla eklendi |
| Zafiyeti doğrulama | `aws s3 ls s3://test-lab-level1/` (imzalı, `--no-sign-request` yok) | ✅ Başarılı — `test.txt` listelendi |
| Grant kaldırma | `put-bucket-acl --acl private` | Grant kaldırıldı |
| Doğrulama | `get-bucket-acl --bucket test-lab-level1` | Sadece Owner `FULL_CONTROL` — `AuthenticatedUsers` girişi yok |

Hesap: `SMHKDR` (`174429081136`), bölge: `us-west-2`, IAM kullanıcı:
`kadir-cli`.

## 6. Kök Neden (Paylaşılan Sorumluluk)

Bu da Level 1 gibi tamamen müşteri tarafı bir yapılandırma hatası — ancak
farklı bir kök nedenle: **S3'ün önceden tanımlı ACL grup isimlendirmesinin
yanlış anlaşılması.** `http://acs.amazonaws.com/groups/global/AuthenticatedUsers`
URI'si kulağa "benim doğruladığım/kendi kullanıcılarım" gibi gelse de, AWS
dokümantasyonunda açıkça belirtildiği üzere bu grup **AWS'e kayıtlı
herhangi bir kullanıcıyı** kapsar — bucket sahibinin uygulamasıyla hiçbir
ilişkisi olmayan, dünyanın herhangi bir yerinden ücretsiz katman bir AWS
hesabı açan biri dahil. Bu isimlendirme tuzağı, S3'te belgelenmiş, sık
karşılaşılan bir yanlış yapılandırma sınıfıdır.

AWS'in Paylaşılan Sorumluluk Modeli çerçevesinde burada da altyapı
(security **of** the cloud) sorumlu değil; hangi principal'a hangi ACL
grubunun atandığına karar vermek müşterinin sorumluluğunda (security **in**
the cloud). AWS bu hata sınıfını da modern varsayılanlarla (Object Ownership'in
"Bucket owner enforced" olması ve Block Public Access'in
`AuthenticatedUsers`'ı da "public" sayması) büyük ölçüde önlüyor — ama bu
korumalar açılabilir/atlanabilir kontroller olduğundan, nihai sorumluluk
yine ACL/bucket policy tasarımını yapan tarafta kalıyor.
