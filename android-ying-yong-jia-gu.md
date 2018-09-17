## Android 应用加固 {#android-应用加固}

### APK 签名校验 {#apk-签名校验}

* 获取公钥的 hashcode

```
public class getSign {
    public static int getSignature(PackageManager pm , String packageName){
    PackageInfo pi = null;
    int sig = 0;
    Signature[]s = null;
    try{
        pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        s = pi.signatures;
        sig = s[0].hashCode();//s[0]是签名证书的公钥，此处获取hashcode方便对比
    }catch(Exception e){
        handleException();
    }
    return sig;
    }
}

```

* app 运行时校验hashcode

```
pm = this.getPackageManager();
int s = getSign.getSignature(pm, "com.hik.getsinature");
if(s != ORIGNAL_SGIN_HASHCODE){//对比当前和预埋签名的hashcode是否一致
    System.exit(1);//不一致则强制程序退出
}

```

### Dex 文件校验 {#dex-文件校验}

通过检测安装后 classes.dex 文件的 hash 值来判断 apk 是否被重打包过。应用发布时，计算 classes.dex 文件的哈希值，并保存在服务器。

1. 读取应用安装目录下
   `/data/app/xxx.apk`
   中的 classes.dex 文件并计算其哈希值，将该值与软件发布时的 classes.dex 哈希值做比较来判断客户端是否被篡改。
2. 读取应用安装目录下
   `/data/app/xxx.apk`
   中的 META-INF 目录下的 MANIFEST.MF 文件，该文件详细记录了 apk 包中所有文件的哈希值，因此可以读取该文件获取到 classes.dex 文件对应的哈希值，将该值与软件发布时的 classes.dex 哈希值做比较就可以判断客户端是否被篡改。

```
private boolean checkcrc(){
    boolean checkResult = false;
    long crc = Long.parseLong(getString(R.string.crc));//获取字符资源中预埋的crc值
    ZipFile zf;
    try{
        String path = getApplicationContext().getPackageCodePath();//获取apk安装路径
        zf = new ZipFile(path);//将apk封装成zip对象
        ZipEntry ze = zf.getEntry("classes.dex");//获取apk中的classes.dex
        long CurrentCRC = ze.getCrc();//计算当前应用classes.dex的crc值
        if(CurrentCRC != crc){//crc值对比
            checkResult = true;
        }
    }catch(IOException e){
        handleError();
        checkResult = false;
    }
    return checkResult;
}

```

### APK 完整性校验 {#apk-完整性校验}

```
1. MessageDigest msgDigest = null;

2. try {

3. msgDigest = MessageDigest.getInstance("MD5")

4. byte[] bytes = new byte[8192];

5. int byteCount;

6. FileInputStream fis = null;

7. fis = new FileInputStream(new File(apkPath));

8. while ((byteCount = fis.read(bytes)) 
>
 0)

9. msgDigest.update(bytes, 0, byteCount);

10. BigInteger bi = new BigInteger(1, msgDigest.digest());

11. String md5 = bi.toString(16);

12. fis.close();

13. /*

14. 从服务器获取存储的 Hash 值，并进行比较

15. */

16. } catch (Exception e) {

17. e.printStackTrace();

18. }

```

### Java 反射技术 {#java-反射技术}

一个可能的应用场景是：根据当前应用程序的状态，从网络服务器获取需要进行反射调用的方法以及参数信息。

### 反调试 {#反调试}

##### 1. 限制调试器连接 {#1-限制调试器连接}

在manifest中设置`Android:debuggable=“false”。`

##### 2. 调试器检测 {#2-调试器检测}

在对 APK 逆向分析时，往往会采取动态调试技术，可以使用 netbeans+apktool 对反汇编 生成的 smali 代码进行动态调试。为了防止 APK 被动态调试，可以检测是否有调试器连接。 Android 系统在 android.os.Debug 类中提供了 isDebuggerConnected\(\)方法，用于检测是否有调 试器连接。可以在 Application 类中调用 isDebuggerConnected\(\)方法，判断是否有调试器连接， 如果有，直接退出程序。

```
if(getApplicationInfo().flags 
&
= ApplicationInfo.FLAG_DEBUGGABLE != 0){
  System.out.println("Debug");
  android.os.Process.killProcess(android.os.Process.myPid());
}

```

### 应用加固技术 {#应用加固技术}

移动应用加固技术从产生到现在，一共经历了三代：

* 第一代是基于类加载器的方式实现保护；
* 第二代是基于方法替换的方式实现保护；
* 第三代是基于虚拟机指令集的方式实现保护。

### 字符串处理 {#字符串处理}

应该尽量避免在源代码中定义字符串常量，比较简单的做法可以使用 StringBuilder 类通过 append方法来构造需要的字符串，或者使用数组的方式来存储字符串。

### 代码乱序技术 {#代码乱序技术}

关于代码乱序的技术，可以参考

ADAM:An automatic and extensible platform to stress test android anti-virus systems 、 DroidChameleon:Evaluating Android Anti-malware against Transformation Attacks。

### 模拟器检测 {#模拟器检测}

分析 APK 的过程中会借助于 Android 模拟器，比如分析网络行为，动态调试等。

### APK 伪加密 {#apk-伪加密}

APK 实际上是 Zip 压缩文件，但是 Android 系统在解析 APK 文件时，和传统的解压缩软件不同，利用这种差异可以实现给 APK 文件加密的功能。Zip文件格式可以参考MasterKey 漏洞分析的一篇文章。在 Central Directory 部分的 File Header 头文件中，有一个 2 字节长的名为 General purpose bit flags 的字段，这个字段中每一位的作用可以参考Zip 文件格式规范的 4.4.4 部分，其中如果第 0 位置 1，则表示 Zip 文件的该 CentralDirectory 是加密的，如果使用传统的解压缩软件打开这个 Zip 文件，在解压该部分 CentralDirectory 文件时，是需要输入密码的。但是 Android 系统在解析 Zip 文件时并没有使用这一位，也就是说这一位是否置位对APK 文件在 Android 系统的运行没有任何影响。一般在逆向 APK 文件时，会首先使用apktool来完成资源文件的解析，dex 文件的反汇编工作，但如果将 Zip 文件中 Central Directory 的 General purpose bit flags 第 0 位置 1 的话，apktool\(version:1.5.2\)将无法完成正常的解析工作，但是又不会影响到 APK 在Android 系统上的正常运行。

### Manifest Cheating {#manifest-cheating}

在 AndroidManifest 的节点中插入一个未知 id\(如 0x0\)，名称为 name 的属性，其值可以是一个从未定义实现的 Java 类文件名。而对 AndroidManifest 的修改需要在二进制格式下进行，这样才能不会破坏之前 aapt 对资源文件的 处理。由于是未知的资源 id，在应用程序运行过程中，Android 会忽略此属性。但是在使用 apktool 进行重打包时，首先会将 AndroidManifest.xml 转换为明文，进而会包含名称为 name 的属性，而相应的 id 信息会丢失，apktool 重打包会重新进行资源打包处理，由于该 name 属性值是一个未实现的 Java 类，重打包后的应用程序在运行过程中，由于 application 节点 中定义的类是先于所有其他组件运行的，若系统找不到对应的类，会出现运行时错误，Dalvik 虚拟机会直接关闭。另外，也可以实现 name 属性值对应的 Java 类，若此类被调用，则表明 被重打包了，可以采取进一步的措施。

具体过程：

* 将 APK 解压缩，提取其中的 AndroidManifest.xml 文件；
* 使用 axml 工具，修改二进制的 AndroidManifest.xml 文件，在 application 节点下插入 id 未知\(如 0x0\)，名为 name 的属性\(值可以任意，只要不对应到项目中的类文件名 即可，如 some.class\)；
* 将除 META-INF 文件夹之外的文件压缩成 zip 文件，签名后生成.apk 文件。



