# About Android Safe {#about-android-safe}

Android 开发中需要面对的种种安全问题主要落在两个方面：1.个人信息的安全存贮，2. 安全访问数据源或者服务器。

开始部分内容来自如下博文，摘抄作者篇首语，学习作者的学习方式。

# 深入理解Android之Java Security（第一部分） {#深入理解android之java-security（第一部分）}

从事[Android](http://lib.csdn.net/base/android)工作4年以来，只有前1年不到的时间是用C++在开发东西（主要是开发DLNA组件，目前我已将它们全部开源，参考[http://blog.csdn\[.NET\]\(http://lib.csdn.net/base/dotnet\)/innost/article/details/40216763），](http://blog.csdn[.net]%28http//lib.csdn.net/base/dotnet%29/innost/article/details/40216763%EF%BC%89%EF%BC%8C%E5%90%8E%E9%9D%A2%E7%9A%84%E5%B7%A5%E4%BD%9C%E5%87%A0%E4%B9%8E%E9%83%BD%E5%9C%A8%E7%94%A8[Java]%28http://lib.csdn.net/base/java%29%E3%80%82%E8%87%AA%E4%BB%A5%E4%B8%BAJava%E7%9B%B8%E5%85%B3%E7%9A%84%E4%B8%9C%E8%A5%BF%E9%83%BD%E8%A7%81%E8%BF%87%E4%BA%86%EF%BC%8C%E5%8F%AF%E5%89%8D%E6%AE%B5%E6%97%B6%E9%97%B4%E6%9C%89%E4%B8%AA%E6%9C%8B%E5%8F%8B%E7%BB%99%E6%88%91%E8%8A%B1%E4%BA%861%E4%B8%AA%E5%A4%9A%E5%B0%8F%E6%97%B6%E8%AE%B2%E8%A7%A3%E4%BB%96%E4%BB%AC%E6%9F%90%E5%A5%97%E7%B3%BB%E7%BB%9F%E7%9A%84%E5%AE%89%E5%85%A8%E4%BD%93%E7%B3%BB%E7%BB%93%E6%9E%84%EF%BC%8C%E5%85%B6%E4%B8%AD%E6%B6%89%E5%8F%8A%E5%88%B0%E5%BE%88%E5%A4%9A%E4%B8%93%E4%B8%9A%E6%9C%AF%E8%AF%AD%EF%BC%8C%E6%AF%94%E5%A6%82Message)后面的工作几乎都在用\[Java\][/\(http://lib.csdn.net/base/java\)](https://frankyzj.gitbooks.io/about-android-safe/content/%28http:/lib.csdn.net/base/java%29)。自以为Java相关的东西都见过了，可前段时间有个朋友给我花了1个多小时讲解他们某套系统的安全体系结构，其中涉及到很多专业术语，比如Message Digest（消息摘要）、Digital Signature（数字签名）、KeyStore（恕我不知道翻译成什么好，还是用英文原称吧）、CA（Certificate Authority）等。我当时脑袋就大了，尼玛搞Java这么久，从来没接触过啊。为此，我特意到AndroidFramework代码中查询了下，[android](http://lib.csdn.net/base/android)平台里与之相关的东西还有一个KeyChain。

原来，上述内容都属于Java世界中一个早已存在的知识模块，那就是JavaSecurity。[Java](http://lib.csdn.net/base/java)Security包含很多知识点，常见的有MD5，DigitalSignature等，而Android在[java](http://lib.csdn.net/base/java)Seurity之外，拓展了一个android.security包，此包中就提供了KeyChain。

本文将介绍Java Security相关的基础知识，然后介绍下Android平台上与之相关的使用场景。

实际上，在一些金融，银行，电子支付方面的应用程序中，JavaSecurity使用的地方非常多。

## 代码路径： {#代码路径：}

* Security.java：libcore/lunl/src/main/java/java/security/
* TrustedCertificateStore.java：libcore /crypto/src/main/java/org/conscrypt/



