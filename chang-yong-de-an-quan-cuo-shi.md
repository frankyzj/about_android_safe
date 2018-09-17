## 常用的安全措施 {#常用的安全措施}

* 在 AndroidManifest 中设置 android:allowBackup 为 false，防止应用数据被直接备份到电脑。但是 root 之后，数据仍然可以被访问。
* 在 activity 中添加 getWindow\(\).addFlags\(WindowManager.LayoutParams.FLAG\_SECURE\)， 防止应用截屏、录屏，防止在最近使用的应用列表中显示缩略图。

#### 保存私密信息到本地的安全策略 {#保存私密信息到本地的安全策略}

绝对不可以使用明文保存在 sharedPreferences 或者数据库。

##### 1. 使用对称加密（例如AES, DES等） {#1-使用对称加密（例如aes-des等）}

密钥不能保存在代码或者手机上，比较好的做法是把部分或者全部密钥放到服务器上。

##### 2. 使用 Android Keystore {#2-使用-android-keystore}

使用 Keystore 保存密钥，相对安全，但是仍然是可以被获取的。

##### 3. 使用非对称加密（例如 RSA） {#3-使用非对称加密（例如-rsa）}

公钥加密，私钥解密。例如，设置密码后，服务器保存一份，使用公钥加密在本地保存一份，需要输入密码时，公钥加密发送到服务器用私钥解密比对即可。

常用的加解密库有[Spongy Castle](https://rtyley.github.io/spongycastle/)和 Google 的[Google Keyczar](https://github.com/google/keyczar)。

