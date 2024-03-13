# <center>**网络安全技术实验报告**</center>

## <center>**Lab1** 基于 DES 加密的 TCP 聊天程序</center>

## <center> **网络空间安全学院 信息安全专业**</center>

## <center> **2112492 刘修铭 1027**</center>

# 一、实验要求

实现基于 DES 加密的 TCP 聊天程序，将“实验报告、源代码、可执行程序”打包后上传，并以自己的“学号-姓名”命名。



# 二、实验目标 

1. 在了解 DES 算法原理的基础上，编程实现对字符串的 DES 加密、解密操作
2. 在了解 TCP 和 Linux 平台下的 Socket 运行原理的基础上，编程实现简单的 TCP 通信
3. 将上述两部分结合到一起，编程实现通信内容事先通过 DES 加密的 TCP 聊天程序，要求双方事先互通密钥，在发送方通过该密钥加密，然后由接收方解密，保证在网络上传输的信息的保密性



# 三、实验内容

1. 实现 DES 加解密算法
2. 实现基于 TCP 协议的一个简易聊天室
3. 将二者结合，聊天室发送的内容需经过 DES 加密



# 四、实验步骤

## （一）DES 加解密算法实现







## （二）基于 TCP 协议的聊天室实现







# 五、实验遇到的问题及其解决方法

## （一）编译工具 cmake 的使用

之前都是在本地 Windows 系统上进行简单的编程，涉及的文件数量有限，编译较为简单。

本学期开始，为了以后项目开发的需要，本人调整编程风格，向规范看齐，规范设置 include、src、build 等文件夹，同时借助 camke 跨平台编译工具，生成 makefile 文件，一键完成对项目的整体编译，免去复杂指令进行编译等问题。



## （二）DES 算法的理解

上学期密码学简单了解过 DES 加解密算法，但未编程实现。这次需要吃透 DES 算法，并自己动手进行编程实现，有一定的挑战性。

本人在实验前通过查阅 CSDN、知乎、GitHub、bilibili 等网站，同时阅读实验参考手册，对 DES 进行了充分的了解，对于后续编程具有极大的帮助。



## （三）实验系统的部署

本人是第一次在 Linux 系统上进行 Socket 编程。但是突遭横祸，Ubuntu 虚拟机无法启动，重装也无济于事。在此情况下，果断改用 WSL，对多系统编程有一定帮助。



# 六、实验结论

本人进行了简单的聊天测试。如图，确定好客户端与服务器端的身份后，即可完成通信连接，即可进行双工通信。

本人测试了中文、英文及阿拉伯数字，客户端与服务器端均能够正常发送与接收。

按照聊天机制设定，输入 `quit`，可以看到成功退出聊天室。

<img src="./report.pic/2e26e179de9e97650a982cdfc0a63c5.png" alt="2e26e179de9e97650a982cdfc0a63c5" style="zoom:50%;" />

另一方输入 `quit`，也可以结束聊天。

<img src="./report.pic/546a6d9fc9f5b09cbd85238838f4e65.png" alt="546a6d9fc9f5b09cbd85238838f4e65" style="zoom:50%;" />

本次实验的完成，说明了本人对于 DES 加解密机制的掌握情况，也说明本人对于 Linux 系统上的 Socket 编程的正确性。



# 七、实验收获

经过本次实验，本人对于 DES 的加解密机制有了充分的了解，对于密码有了进一步的掌握。同时，对于 Linux 系统上的 Socket 编程等有了进一步掌握，有助于后续的实验开发。除此之外，还学习到了 cmake 跨平台编译工具，对于日后项目开发有较大帮助。



# 八、实验参考

本次实验除参考下发的实验文档外，还参考了如下教程：

[https://blog.csdn.net/weixin_61823031/article/details/123053269](https://blog.csdn.net/weixin_61823031/article/details/123053269)
[https://zhuanlan.zhihu.com/p/315795886](https://zhuanlan.zhihu.com/p/315795886)
[https://github.com/Drummerboy458/DES-](https://github.com/Drummerboy458/DES-)
[https://blog.csdn.net/baiye1203/article/details/110623598](https://blog.csdn.net/baiye1203/article/details/110623598)
[https://www.iteye.com/resource/lzq824912291-2491506](https://www.iteye.com/resource/lzq824912291-2491506)
[https://github.com/KuGmonkey/TCP_DES](https://github.com/KuGmonkey/TCP_DES)
[https://github.com/OREOo-o/Des-encryption-for-TCP-chat](https://github.com/OREOo-o/Des-encryption-for-TCP-chat)
[https://blog.51cto.com/u_15169172/4859590](https://blog.51cto.com/u_15169172/4859590)
