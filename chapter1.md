# 需要知道的一些词儿 {#需要知道的一些词儿}

[http://blog.csdn.net/Innost/article/details/44081147](http://blog.csdn.net/Innost/article/details/44081147)（对比加粗重点代码）

Message Digest（消息摘要）、Digital Signature（数字签名）、KeyStore、CA（Certificate Authority），KeyChain。

#### Java Security包含主要三个重要的规范： {#java-security包含主要三个重要的规范：}

* Java Cryptography Extension（简写为JCE），JCE所包含的内容有加解密，密钥交换，消息摘要（Message Digest，比如MD5等），密钥管理等。
* Java Secure Socket Extension（简写为JSSE），JSSE所包含的内容就是Java层的SSL/TLS。简单点说，使用JSSE就可以创建SSL/TLS socket了。
* Java Authentication and Authorization Service（简写为JAAS），JSSA和认证/授权有关。这部分内容在客户端接触得会比较少一点。

Android平台上，每一个应用程序在启动的时候都会默认注册一个类型为AndroidKeyStoreProvider的对象。

## 1. JCE {#1-jce}

### 1.1 KEY {#11-key}

![](https://frankyzj.gitbooks.io/about-android-safe/content/assets/20150305131702403.png)

上图中：

* Key怎么创建？在JCE中是通过Generator类创建的，这时候在代码中得到的是一个Key实例对象。

* Key怎么传递？这就涉及到如何书面表达Key了，最最常用的方式就是把它表示成16进制（比如图4中下部Encoded Key Data“0AF34C4E56...”）。或者，因为Key产生是基于算法的，这时候就可以把参与计算的关键变量的值搞出来。比如图4右上角的“Param P=3，ParamQ=4”。所以，Key的书面表达形式有两种，一种是16进制密钥数据，一种是基于算法的关键变量（这种方式叫KeySpecification）。

* 此后，我们可以把16进制或者关键变量发给对方。对方拿到Key的书面表达式后，下一步要做的就是还原出代码中的key对象。这时候要用到的就是KeyFactory了。所以，KeyFactory的输入是Key的二进制数据或者KeySpecification，输出就是Key对象。

在安全领域中，Key分为两种：

* 对称Key：即加密和解密用得是同一个Key。JCE中，对称key的创建由KeyGenerator类来完成。
* 非对称Key：即加密和解密用得是两个Key。这两个Key构成一个Key对（KeyPair）。其中一个Key叫公钥（PublicKey），另外一个Key叫私钥（PrivateKey）。公钥加密的数据只能用私钥解密，而私钥加密的数据只能用公钥解密。私钥一般自己保存，而公钥是需要发给合作方的。JCE中，非对称Key的创建由KeyPairGenerator类来完成。

生成 Key ：

```
DemoActivity.java；
testKey()
{//对称key即SecretKey创建和导入
     //假设双方约定使用DES算法来生成对称密钥

     e(TAG,"==
>
secret key: generated it using DES");
     KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");

     //设置密钥长度。注意，每种算法所支持的密钥长度都是不一样的。DES只支持64位长度密钥
     //（也许是算法本身的限制，或者是不同Provider的限制，或者是政府管制的限制）
     keyGenerator.init(64);

     //生成SecretKey对象，即创建一个对称密钥
     SecretKey secretKey = keyGenerator.generateKey();

     //获取二进制的书面表达
     byte[] keyData =secretKey.getEncoded();

     //日常使用时，一般会把上面的二进制数组通过Base64编码转换成字符串，然后发给使用者
     String keyInBase64 =Base64.encodeToString(keyData,Base64.DEFAULT);
     e(TAG,"==
>
secret key: encrpted data ="+ bytesToHexString(keyData));
     e(TAG,"==
>
secrety key:base64code=" + keyInBase64);
     e(TAG,"==
>
secrety key:alg=" + secretKey.getAlgorithm());

     //假设对方收到了base64编码后的密钥，首先要得到其二进制表达式
     byte[] receivedKeyData = Base64.decode(keyInBase64, Base64.DEFAULT);

     //用二进制数组构造KeySpec对象。对称key使用SecretKeySpec类
     SecretKeySpec keySpec =new SecretKeySpec(receivedKeyData,”DES”);

     //创建对称Key导入用的SecretKeyFactory
     SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(”DES”);

     //根据KeySpec还原Key对象，即把key的书面表达式转换成了Key对象
     SecretKey receivedKeyObject = secretKeyFactory.generateSecret(keySpec);
     byte[] encodedReceivedKeyData = receivedKeyObject.getEncoded();
     e(TAG,"==
>
secret key: received key encoded data ="
                                +bytesToHexString(encodedReceivedKeyData));
 }

```

如果一切正常的话，encrpted data 和 received key encoded data 打印出的二进制表示应该完全一样。

生成 KeyPair :

```
DemoActivity.java;
KeyPair()
{//public/private key test
  e(TAG, "==
>
keypair: generated it using RSA");
  //使用RSA算法创建KeyPair
  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
  //设置密钥长度
  keyPairGenerator.initialize(1024);
  //创建非对称密钥对，即KeyPair对象
  KeyPair keyPair =keyPairGenerator.generateKeyPair();
  //获取密钥对中的公钥和私钥对象
  PublicKey publicKey =keyPair.getPublic();
  PrivateKey privateKey =keyPair.getPrivate();
  //打印base64编码后的公钥和私钥值
  e(TAG,"==
>
publickey:"+bytesToHexString(publicKey.getEncoded()));
  e(TAG, "==
>
privatekey:"+bytesToHexString(privateKey.getEncoded()));

  /*
   现在要考虑如何把公钥传递给使用者。虽然可以和对称密钥一样，把二进制数组取出来，但是
   对于非对称密钥来说，JCE不支持直接通过二进制数组来还原KeySpec（可能是算法不支持）。
   那该怎么办呢？前面曾说了，除了直接还原二进制数组外，还可以通过具体算法的参数来还原
   RSA非对称密钥就得使用这种方法：
   1 首先我们要获取RSA公钥的KeySpec。
  */
  //获取RSAPublicKeySpec的class对象
  Class spec = Class.forName("java.security.spec.RSAPublicKeySpec");
   //创建KeyFactory，并获取RSAPublicKeySpec
  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  RSAPublicKeySpec rsaPublicKeySpec =
            (RSAPublicKeySpec)keyFactory.getKeySpec(publicKey, spec);
  //对RSA算法来说，只要获取modulus和exponent这两个RSA算法特定的参数就可以了
  BigInteger modulus =rsaPublicKeySpec.getModulus();
  BigInteger exponent =rsaPublicKeySpec.getPublicExponent();
  //把这两个参数转换成Base64编码，然后发送给对方
  e(TAG,"==
>
rsa pubkey spec:modulus="+
             bytesToHexString(modulus.toByteArray()));
  e(TAG,"==
>
rsa pubkey spec:exponent="+
             bytesToHexString(exponent.toByteArray()));

  //假设接收方收到了代表modulus和exponent的base64字符串并得到了它们的二进制表达式
  byte[] modulusByteArry = modulus.toByteArray();
  byte[] exponentByteArry = exponent.toByteArray();
  //由接收到的参数构造RSAPublicKeySpec对象
  RSAPublicKeySpec receivedKeySpec = new RSAPublicKeySpec(
                    new BigInteger(modulusByteArry),
                    new BigInteger(exponentByteArry));
  //根据RSAPublicKeySpec对象获取公钥对象
  KeyFactory receivedKeyFactory = keyFactory.getInstance("RSA");
  PublicKey receivedPublicKey =
                 receivedKeyFactory.generatePublic(receivedKeySpec);
  e(TAG, "==
>
received pubkey:"+
                   bytesToHexString(receivedPublicKey.getEncoded()));
}

```

如果一切正常的话，上述代码中 publickey 和 received pubkey 段将输出完全一样的公钥二进制数据。

在Android平台的JCE中，非对称Key的常用算法有“RSA”、“DSA”、“Diffie−Hellman”、“Elliptic Curve \(EC\)”等。

### 1.2 CERTIFICATES {#12-certificates}

一般而言，我们会把 Key 的二进制表达式放到证书里，证书本身再填上其他信息（比如此证书是谁签发的，什么时候签发的，有效期多久，证书的数字签名等等）。

#### 根证书（root key）和证书链（key chain） {#根证书（root-key）和证书链（key-chain）}

为了方便，系统（PC，Android，甚至浏览器）等都会把一些顶级CA（也叫Root CA，即根CA）的证书默认集成到系统里。这些RootCA用作自己身份证明的证书（包含该CA的公钥等信息）叫根证书。根证书理论上是需要被信任的。以Android为例，它在libcore/luni/src/main/files/cacerts下放了150多个根证书。

* 证书有很多格式，但是目前通用格式为X.509格式。

#### 常见的证书文件格式，一般用文件后缀名标示。 {#常见的证书文件格式，一般用文件后缀名标示。}

* .pem（Privacy-enhanced ElectronicMail\) Base64 编码的证书，编码信息（即将示例中X.509证书的明文内容用Base64编码后得到的那个字符串）放在"-----
  **BEGIN CERTIFICATE**
  -----" and "-----
  **END CERTIFICATE**
  -----"之间。所以，Android平台里的根CA文件都是PEM证书文件。
* .cer,.crt, .der：证书内容为ASCII编码，二进制格式，但也可以和PEM一样采用base64编码。
* .p7b,.p7c – PKCS\#7（Public-Key CryptographyStandards ，是由RSA实验室与其它安全系统开发商为促进公钥密码的发展而制订的一系列标准，\#7表示第7个标准，PKCS一共有15个标准）封装的文件。其中，p7b可包含证书链信息，但是不能携带私钥，而p7c只包含证书。
* .p12– PKCS\#12标准,可包含公钥或私钥信息。如果包含了私钥信息的话，该文件内容可能需要输入密码才能查看。

#### 证书的导入 {#证书的导入}

```
void testCertificate() {
    e(TAG, "***Begintest Certificates***");
    try {
      //在res/assets目录下放了一个名为“my-root-cert.pem”的证书文件
      AssetManager assetManager = this.getAssets();
      InputStream inputStream = assetManager.open("my-root-cert.pem");

      //导入证书得需要使用CertificateFactory，
      CertificateFactory certificateFactory =
                      CertificateFactory.getInstance("X.509");
      /*
      从 my-root-cert.pem 中提取 X509 证书信息，并保存在 X509Certificate 对象中
      注意，如果一个证书文件包含多个证书（证书链的情况），generateCertificate 将只返回
      第一个证书
      调用generateCertificates函数可以返回一个证书数组，
      */
      X509Certificate myX509Cer =
          (X509Certificate)certificateFactory
              .generateCertificate(inputStream);
     //打印X509证书的一些信息。DN是Distinguished Name。DN通过设定很多项（类似于地址
     //一样，比如包括国家、省份、街道等信息）来唯一标示一个持有东西（比如发布此证书的机构等）
      e(TAG, "==
>
SubjecteDN:" + myX509Cer.getSubjectDN().getName());
      e(TAG,"==
>
Issuer DN:" + myX509Cer.getIssuerDN().getName());
      e(TAG,"==
>
Public Key:"
          +bytesToHexString(myX509Cer.getPublicKey().getEncoded()));
      inputStream.close();
    } ......
    }

    e(TAG, "***End testCertificates***");
  }

```

* CertificateFactory只能导入pem、der格式的证书文件。

### 1.3 KEY 的管理 {#13-key-的管理}

* keystore：keystore就是存储Key的一个文件。JCE为KeyStore设置了一些API，通过这些API，我们可以操作一个KeyStore。

* alias：别名。在KeyStore中，每一个存储项都对应有一个别名。别名就是方便你找到Key的。

* KeyStore 里边存储的东西可分为两种类型。一种存储类型叫**Key Entry**：KE可携带KeyPair，或者SecretKey信息。如果KE存储的是KeyPair的话，它可能会携带一整条证书链信息。另外一种存储类型是**Certificate Entry**：CE用于存储根证书。根证书只包含公钥。而且CE一般对应的是可信任的CA证书，即顶级CA的证书。这些证书存储在xxx/**cacerts**目录下。

```
void testKeyStore() {

    e(TAG, "***Begintest KeyStore***");
    try {
      AssetManager assetManager = this.getAssets();

      //assets目录下放了一个pkcs12的证书文件
      InputStream inputStream = assetManager.open("test-keychain.p12");

     //创建KeyStore实例
      KeyStore myKeyStore = KeyStore.getInstance("PKCS12");

     /*
      KeyStore实例默认是不关联任何文件的，所以需要用keystore文件来初始化它。
      load函数：第一个参数代表keystore文件的InputStream
      第二个参数是keystore文件的密码。和保险箱类似，KeyStore文件本身是用密码保护的
      一些KeyStore文件的默认密码叫“changeit”。
      如果不传密码的话，KeyStore初始化后，只能取出公开的证书信息。注意，不同KeyStore
      实现方法对此处理情况不完全相同。
     */
      myKeyStore.load(inputStream,"changeit".toCharArray());

      //就本例而言，KeyStore对象所代表KeyStore实际上就是test-keychain.p12文件
      //获取KeyStore中定义的别名
     Enumeration
<
String
>
 aliasEnum = myKeyStore.aliases();
      while(aliasEnum.hasMoreElements()) {
        String alias =aliasEnum.nextElement();
        //判断别名对应的项是CE还是KE。注意,CE对应的是可信任CA的根证书。
        boolean bCE =myKeyStore.isCertificateEntry(alias);
        boolean bKE =myKeyStore.isKeyEntry(alias);
       //本例中，存储的是KE信息
       e(TAG,"==
>
Alias:"+alias + " is CE:"+bCE + "is KE:"+bKE);
        //从KeyStore中取出别名对应的证书链
        Certificate[] certificates = myKeyStore.getCertificateChain(alias);

       //打印证书链的信息
        for (Certificate cert: certificates) {
          X509Certificate myCert = (X509Certificate) cert;
          e(TAG,"==
>
I am a certificate:"  );
          e(TAG,"==
>
Subjecte DN:" + myCert.getSubjectDN().getName());
          e(TAG,"==
>
Issuer DN:" + myCert.getIssuerDN().getName());
          e(TAG,"==
>
Public Key:"+ bytesToHexString(myCert.getPublicKey()
                 .getEncoded()));
        }

        //取出别名对应的Key信息，一般取出的是私钥或者SecretKey。
       // 注意，不同的别名可能对应不同的Entry。本例中，KE和CE都使用一样的别名
        Key myKey = myKeyStore.getKey(alias,"changit".toCharArray());
        if(myKey instanceof PrivateKey){
          e(TAG,"==
>
I am a private key:" +
                             bytesToHexString(myKey.getEncoded()));
        } else if(myKeyinstanceof SecretKey){
          if(myKey instanceofPrivateKey){
            e(TAG,"==
>
I am a secret key:" +
                             bytesToHexString(myKey.getEncoded()));
          }
        }

      }
    } ......
e(TAG, "***Endtest KeyStore***");

```

* Android平台有一个系统范围内统一的KeyStore。由于Android代码也遵循 JCE 规范，所以这个统一的 KeyStore 是通过 AndroidKeyStoreProvider 注册上去的。只要在 KeyStore.getInstance 的参数传递 “AndroidKeyStore”，你就能得到Android系统级别的 KeyStore 了。

  系统级别的KeyStore有啥好处呢？很明显，当我们把一个证书导入到系统级别的KeyStore后，其他应用程序就可以使用了。而且，Android系统对这个KeyStore保护很好，甚至要求用硬件实现KeyStore保护！

### 1.4 Message Digest 和 Signature {#14-message-digest-和-signature}

#### MD的作用是为了防止数据被篡改： {#md的作用是为了防止数据被篡改：}

* 数据发布者：对预发布的数据进行MD计算，得到MD值，然后放到一个公开的地方。
* 数据下载者：下载数据后，也计算MD值，把计算值和发布者提供的MD值进行比较，如果一样就表示下载的数据没有被篡改。

```
void testMessageDigest(){
    e(TAG, "***Begintest MessageDigest***");
    try {
      //创建一个MD计算器，类型是MessageDigest，计算方法有MD5，SHA等。
      MessageDigest messageDigest = MessageDigest.getInstance("MD5");

      //消息数据
      String  data = "This is a message:)";
      e(TAG,"==
>
Message is:" + data);

      //计算MD值时，只要不断调用MessageDigest的update函数即可，其参数是待计算的数据
      messageDigest.update(data.getBytes());

      //获取摘要信息，也是用二进制数组表达
      byte[] mdValue = messageDigest.digest();
      e(TAG,"==
>
MDValue is:"+bytesToHexString(mdValue));

      //重置MessageDigest对象，这样就能重复使用它
      messageDigest.reset();

      AssetManager assetManager = this.getAssets();
      InputStream inputStream= assetManager.open("test-keychain.p12");

      //这次我们要计算一个文件的MD值
      e(TAG,"==
>
Message is a file:" + "test-keychain.p12");

      //创建一个DigestInputStream对象，需要将它和一个MD对象绑定
      DigestInputStream digestInputStream = new DigestInputStream(inputStream,
                         messageDigest);
      byte[] buffer = newbyte[1024];

      //读取文件的数据，DigestInputStream内部会调用MD对象计算MD值
     while(digestInputStream.read(buffer)
>
 0){

      }
      //文件读完了，MD也计算出来了
      mdValue =messageDigest.digest();
      e(TAG,"==
>
MDValue is:"+bytesToHexString(mdValue));

     digestInputStream.close();
      inputStream.close();

      /*
      MD值其实并不能真正解决数据被篡改的问题。因为作假者可以搞一个假网站，然后提供
      假数据和根据假数据得到的MD值。这样，下载者下载到假数据，计算的MD值和假网站提供的
      MD数据确实一样，但是这份数据是被篡改过了的。
      解决这个问题的一种方法是：计算MD的时候，输入除了消息数据外，还有一个密钥。
      由于作假者没有密钥信息，所以它在假网站上上提供的MD肯定会和数据下载者根据密钥+假
      数据得到的MD值不一样。
      这种方法得到的MD叫Message Authentication Code，简称MAC
     */
      e(TAG,"==
>
Calcualte MAC");

      //创建MAC计算对象，其常用算法有“HmacSHA1”和“HmacMD5”。其中SHA1和MD5是
      //计算消息摘要的算法，Hmac是生成MAC码的算法
      Mac myMac = Mac.getInstance("HmacSHA1");

      //计算my-root-cert.pem的MAC值
      inputStream =assetManager.open("my-root-cert.pem");

      //创建一个SecretKey对象
      KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
      keyGenerator.init(64);
      SecretKey key = keyGenerator.generateKey();

      //用密钥初始化MAC对象
      myMac.init(key);

      buffer = newbyte[1024];
      int nread = 0;

      //计算文件的MAC
      while ((nread = inputStream.read(buffer)) 
>
 0) {
        myMac.update(buffer, 0, nread);
      }
      //得到最后的MAC值
      byte[] macValue =myMac.doFinal();
      e(TAG, "==
>
MACValue is:" + bytesToHexString(macValue));

      inputStream.close();

    } 
    e(TAG, "***End testMessageDigest***");
  }

```

#### Signature {#signature}

* 数据发送者先计算数据的摘要，然后利用私钥对摘要进行签名操作，得到一个签名值。

* 数据接收者下载数据和签名值，也计算摘要。然后用公钥对摘要进行操作，得到一个计算值。然后比较计算值和下载得到的签名值，如果一样就表明数据没有被篡改。

* 为了防止证书被篡改，我们在证书里边往往也会包含签名信息。证书A的签名信息其实是上一级的CA（假设为B）利用B的私钥对证书A进行签名操作，然后把这个签名值放到证书A里边。如果要验证证书A是否被篡改的话，我们需要CA B的证书B，因为证书B会提供CA B的公钥。明白了吧？，所以证书校验会是一个链式的情况。当最后校验到根CA的时候，由于根CA是利用自己的私钥对自己的证书进行签名，然后把自己的公钥，签名放到根证书里边。所以这个链最后就会终止在根证书这了

```
 void testSignature(){
    e(TAG, "***Begintest Signature***");
    try {
      AssetManager assetManager = this.getAssets();

       //本例中，私钥和公钥信息都放在test-keychain.p12文件中，我们先从里边提取它们
      InputStream inputStream = assetManager.open("test-keychain.p12");

      KeyStore myKeyStore = KeyStore.getInstance("PKCS12");
      myKeyStore.load(inputStream, "changeit".toCharArray());

      String alias = "MyKey Chain";
      Certificate cert = myKeyStore.getCertificate(alias);
      PublicKey publicKey = cert.getPublicKey();

      PrivateKey privateKey =(PrivateKey)myKeyStore.getKey(alias,
                              "changit".toCharArray());
      inputStream.close();

      //对my-root-cert.pem进行签名
      e(TAG, "==
>
start sign of file : my-root-cert.pem");

       //MD5表示MD的计算方法，RSA表示加密的计算方法。常用的签名算法还有“SHA1withRSA”
       //“SHA256withRSA”
      Signature signature = Signature.getInstance("MD5withRSA");

      //计算签名时，需要调用initSign，并传入一个私钥
      signature.initSign(privateKey);
      byte[] data = newbyte[1024];
      int nread = 0;
      InputStream inputStreamToBeSigned = assetManager.open(
                             "my-root-cert.pem");
      while((nread =inputStreamToBeSigned.read(data))
>
0){
        signature.update(data, 0, nread);//读取文件并计算签名
      }
      //得到签名值
      byte[] sig = signature.sign();

      e(TAG, "==
>
Signed Signautre:" + bytesToHexStaring(sig));
      signature = null;
      inputStreamToBeSigned.close();

       //校验签名
      e(TAG, "==
>
start verfiy of file : my-root-cert.pem");
      inputStreamToBeSigned = assetManager.open("my-root-cert.pem");
      signature = Signature.getInstance("MD5withRSA");

      //校验时候需要调用initVerify，并传入公钥对象
      signature.initVerify(publicKey);
      data = new byte[1024];
      nread = 0;
      while((nread =inputStreamToBeSigned.read(data))
>
0){
        signature.update(data, 0, nread);//读取文件并计算校验值
      }

      //比较签名和内部计算得到的检验结果，如果一致，则返回true
      boolean isSigCorrect =signature.verify(sig);
      e(TAG, "==
>
IsSignature Correct :" + isSigCorrect);

     inputStreamToBeSigned.close();

    } catch (Exception e) {
      e(TAG," " +e.getMessage());
    }
    e(TAG, "***End testSignature***");
  }

```

### 1.5 加解密 {#15-加解密}

主要用到一个Class就是Cipher。Cipher类实例在创建时需要指明相关算法和模式（即Cipher.getInstance的参数）。根据JCE的要求：

* 可以仅指明“算法”，比如“DES”。
* 要么指明“算法/反馈模式/填充模式”（反馈模式和填充模式都和算法的计算方式有关），比如“AES/CBC/PKCS5Padding”。

JCE中，

* 常见的算法有“DES”，“DESede”、“PBEWithMD5AndDES”、“Blowfish”。
* 常见的反馈模式有“ECB”、“CBC”、“CFB”、“OFB”、“PCBC”。
* 常见的填充模式有“PKCS5Padding”、“NoPadding”。

```
void testCipher(){
try {
      //加解密要用到Key，本例使用SecretKey进行对称加解密运算
      KeyGenerator  keyGenerator = KeyGenerator.getInstance("DES");
      SecretKey key = keyGenerator.generateKey();

      //待加密的数据是一个字符串
      String data ="This is our data";
      e(TAG, "==
>
RawData : " + data);
      e(TAG, "==
>
RawData in hex: " + bytesToHexString(data.getBytes()));

     //创建一个Cipher对象，注意这里用的算法需要和Key的算法匹配
      Cipher encryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");

      //设置Cipher对象为加密模式，同时把Key传进去
      encryptor.init(Cipher.ENCRYPT_MODE, key);

      //开始加密，注意update的返回值为输入buffer加密后得到的数据，需要保存起来
      byte[] encryptedData = encryptor.update(data.getBytes());

      //调用 doFinal 以表示加密结束。doFinal 有可能也返回一串数据，也有可能返回null。因为
      byte[] encryptedData1 = encryptor.doFinal();

     //finalEncrpytedData为最终加密后得到的数据，它是update和doFinal的返回数据的集合
      byte[] finalEncrpytedData =
             concateTwoBuffers(encryptedData, encryptedData1);
      e(TAG, "==
>
EncryptedData : " + bytesToHexString(finalEncrpytedData));

      //获取本次加密时使用的初始向量。初始向量属于加密算法使用的一组参数。使用不同的加密算法
      //时，需要保存的参数不完全相同。Cipher会提供相应的API
      byte[] iv = encryptor.getIV();
      e(TAG,"==
>
Initial Vector of Encryptor: " + bytesToHexString(iv));

      /*
         解密：解密时，需要把加密后的数据，密钥和初始向量发给解密方。
         再次强调，不同算法加解密时，可能需要加密对象当初加密时使用的其他算法参数
       */
      Cipher decryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

      //设置Cipher为解密工作模式，需要把Key和算法参数传进去
      decryptor.init(Cipher.DECRYPT_MODE, key,ivParameterSpec);

      //解密数据，也是调用update和doFinal
      byte[] decryptedData =decryptor.update(finalEncrpytedData);
      byte[] decryptedData1 =decryptor.doFinal();

      //将数据组合到一起，得到最终的数据
      byte[] finaldecrpytedData =
               concateTwoBuffers(decryptedData, decryptedData1);
      e(TAG,"==
>
Decrypted Data  in hex:" +
                  bytesToHexString(finaldecrpytedData));
      e(TAG,"==
>
Decrypted Data  : " + newString(finaldecrpytedData));
    } ......
    e(TAG, "***End testCipher***");
  }

```

## 2. JSSE {#2-jsse}

JSSE实际上Java平台对SSL/TLS的某种实现。

* JCE中，我们见到过KeyStore，KeyStore就像个保险箱似的，能存储证书文件。在JSSE中，有一个类似的概念，叫TrustStore。TrustStore和KeyStore其实从编程角度看都是ClassKeyStore，二者的区别主要体现在用途上。

* SSL中，客户端需要连接服务端。比如客户端是个浏览器，它可以连接很多很多服务器。那么，根据刚才所说，这些服务器需要把自己的证书发给浏览器的。浏览器收到证书后，需要验证它们。由于证书链的事情，最终都会验证到根证书那。前面也提到过，有很多根CA，根CA又可能签发不同用途的根证书。为了方便，系统往往会集成一些常用的根证书，放到一个统一的目录下（比如前面在Android提到的cacerts文件夹下放的150多个根证书文件），或者放到一个文件里（在台式机上，一般放在jre目录/lib/security/cacerts文件中）。有了TrustStore，我们就可以利用其中存储的根证书了。

* 相比较而言，KeyStore一般存储的是私钥等相关信息。但从技术上说，KeyStore和TrustStore可以是同一个文件。这个由具体实现来定。在Android平台上，系统级的KeyStore（也就是前面提到的AndroidKeyStore）和TrustStore是同一个东西。

#### 使用案例 {#使用案例}

这个案例分两个部分，一个是服务端，另外一个是客户端。服务端类似于一个echo服务器，即打印客户端发来的一个字符串。

由前述内容可知，服务端需要keystore，该keystore保存了私钥信息，因为服务端要用它来为证书签名。

```
private void startServer(){
    //Server单独跑在一个线程里
    Thread serverThread = newThread(new Runnable() {
      @Override
      public void run() {
        try {
          e(TAG,"==
>
prepare keystore for server:");
          ServerSocketFactory serverSocketFactory = null;

         //下面这段代码在testKeyStore的时候介绍过。本例中，私钥，证书文件其实都存在
         //test-keychain.p12文件里
          AssetManager assetManager= DemoActivity.this.getAssets();
          InputStream keyInputStream = assetManager.open("test-keychain.p12");
          KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");

          //初始化KeyStore
          serverKeyStore.load(keyInputStream,"changeit".toCharArray());
          keyInputStream.close();

          //我们要用这个keystore来初始化一个SSLContext对象。SSLContext使得我们
          //能够控制 SSLSocket 和 KeyStore，TrustStore 相关的部分，而不是使用系统默认值
          SSLContext sslContext = SSLContext.getInstance("TLS");
          KeyManagerFactory keyManagerFactory = KeyManagerFactory
              .getInstance(KeyManagerFactory.getDefaultAlgorithm());

         //先用KeyStore对象初始化KeyManagerFactory
          keyManagerFactory.init(serverKeyStore,"changeit".toCharArray());

          /*
           然后初始化SSLContext，init函数有三个参数，第一个是KeyManager数组，
           第二个是TrustManager数组，第三个是SecureRandom，用来创建随机数的
            显然，第一个参数用来创建服务端Socket的，而第二个参数用于创建客户端Socket
          */
          sslContext.init(keyManagerFactory.getKeyManagers(), null,null);
          e(TAG,"==
>
start server:");

          //得到服务端socket创建工厂对象
          serverSocketFactory = sslContext.getServerSocketFactory();

          //在localhost:1500端口号监听
          InetAddress listenAddr = Inet4Address.getLocalHost();
          ServerSocket serverSocket = serverSocketFactory
              .createServerSocket(1500, 5,listenAddr);

          //启动客户端，待会再分析这个函数
          startClient();
          //接收数据并打印，然后关闭服务端
          Socket clientSock = serverSocket.accept();
          InputStream inputStream = clientSock.getInputStream();
          byte[] readBuffer = new byte[1024];
          int nread = inputStream.read(readBuffer);
          e(TAG,"==
>
echo from Client:" + new String(readBuffer, 0, nread));
          clientSock.close();
          serverSocket.close();
        } ......
        e(TAG,"==
>
server quit");
      }
    });
    serverThread.start();
  }

```

**特别注意：**如果不使用SSLContext话，我们可以直接调用**SSLServerSocketFactory**的getDefault函数返回一个ServerSocketFactory。但是这个工厂创建的ServerSocket在accept的时候会出错。出错的原因是“**Could not find anykey store entries to support the enabled cipher suites.**”，也就是说，找不到Keystore有哪一个KE能支持所使用的加解密算法。报错的代码在libcore/crypto/src/main/java/org/conscrypt/SSLServerSocketFactory的checkEnabledCipherSuites函数中。这个函数会检查几种常见的Key类型（比如RSA等），然后检查KeyStore里有没有这种类型的PrivateKey，如果没有就报错。

其实，SSLServerSocketFactory内部也会查找和绑定一个KeyStore，这些操作和我们在示例代码中看到的几乎一样，只不过它们使用默认的KeyStore来创建罢了。为了保持Java的一致性，Android里边JCE的默认属性和PC上是一样的，它并没有利用Android系统统一的“AndroidKeyStore”替换。

注意：即使我们创建一个AndroidKeyStore类型的KeyStore传到SSLContext里，我们也无法使用。为什么？因为Android平台有自己的一套Key管理。我们后续分析代码的时候会见到。

```
private void startClient(){

    Thread clientThread = newThread(new Runnable() {
      @Override
      public void run() {
        try {
          e(TAG,"==
>
prepare client truststore");
          SocketFactory socketFactory = null;

          //注意，如果我们把证书文件导入到Android系统后，就可以利用默认的设置来创建
          //客户端Socket工厂了，否则还得和服务端一样，自己绑定TrustStore！
          if (isOurKeyChainAvailabe()) {
            e(TAG, "wehave installed key in the system");
            socketFactory = SSLSocketFactory.getDefault();
          } else {
            e(TAG,"prepare truststore manually");
            AssetManager assetManager = DemoActivity.this.getAssets();
            InputStream keyInputStream = assetManager
               .open("test-keychain.p12");

           //客户端Socket工厂用TrustManagerFactory来构造
           TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
           KeyStore keyStore= KeyStore.getInstance("PKCS12");
           keyStore.load(keyInputStream, "changeit".toCharArray());
           keyInputStream.close();

            //用KeyStore来初始化TrustManagerFactory
            tmf.init(keyStore);

            //同样是创建一个SSLContext对象
            SSLContext sslContext = SSLContext.getInstance("TLS");

            //初始化SSLContext，这个时候只要传递第二个参数就可以了
            sslContext.init(null, tmf.getTrustManagers(), null);
            socketFactory = sslContext.getSocketFactory();
          }

          e(TAG,"==
>
start client:");

          //连接到服务端
          InetAddress serverAddr = Inet4Address.getLocalHost();
          Socket mySocket =socketFactory.createSocket(serverAddr,1500);
          OutputStream outputStream = mySocket.getOutputStream();
          //发送数据并退出
          String data ="I am client";
          e(TAG,"==
>
Client sent:" + data);
          outputStream.write(data.getBytes());
          mySocket.close();
        } ......
        e(TAG,"==
>
client quit");
      }
    });
    clientThread.start();
  }

```

注意，如果我们没有导入证书，并且也没有显示得绑定证书文件，那么在 createSocket 的时候会报错，报错的原因很简单，就是说本地的 TrustStore 里边没有证书来验证服务端的身份。为什么没有呢？因为服务端用的东西是自己签发的证书，也就是没有根CA来给它盖章。这样的证书发给了客户端，客户端默认使用系统 TrustStore（名为“AndroidCAStore”） 里边没有任何这个证书的信息，所以无法验证。

##### 备注： {#备注：}

文中“对于非对称密钥来说，JCE不支持直接通过二进制数组来还原KeySpec（可能是算法不支持）。”这种说法是错误的，实际上是支持的。

//发送方：

PublicKey publicKey = .... //从某途径获得公钥

byte\[\] encodedKey = publicKey.getEncoded\(\); //得到公钥的二进制数组\(DER编码\)形式

//把这个数组保存为文件或通过网络传送给接收方

//接收方：

KeyFactory kf = KeyFactory.getInstance\("RSA"\); //或者是DSA、ECDSA

byte\[\] encodedKey = .... //从某途径获得公钥的二进制数组

X509EncodedKeySpec keySpec = new X509EncodedKeySpec\(encodedKey\);

RSAPublicKey publicKey = \(RSAPublicKey\) kf.generatePublic\(keySpec\);

//这个publicKey就是还原后的结果

私钥的还原也是类似的办法，只是有关的类不是X509EncodedKeySpec而是PKCS8EncodedKeySpec。

实际应用中，一般不会传送公钥的，常见的做法是传送数字证书，然后从证书里把公钥提取出来。另外除非很有必要，私钥基本不会传来传去的。

参考本人的另一篇文章：Android 中文数字证书解释

