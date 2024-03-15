# <center>**网络安全技术实验报告**</center>

<center>Lab1 基于 DES 加密的 TCP 聊天程序</center>

<center> 网络空间安全学院 信息安全专业</center>

<center> 2112492 刘修铭 1027</center>

## 实验要求

实现基于 DES 加密的 TCP 聊天程序，将“实验报告、源代码、可执行程序”打包后上传，并以自己的“学号-姓名”命名。



## 实验目标 

1. 



## 实验内容

1. 



## 实验步骤

### DES 加解密算法实现



## 实验遇到的问题及其解决方法

### 非静态成员引用必须与特定对象相对

在进行编程时，多次遇到该问题。经过查询得知，在 C++ 中，非静态成员函数或变量需要通过对象来访问。即无法直接在类的定义中引用非静态成员，而需要通过对象来访问它们。基于此，将 `CRsaOperate` 类中的函数均定义为静态函数。

而对于实验指导书中给出的 `CRandom` 类的 `Random` 函数，经过分析，该函数意为求取 base 范围内的随机数，故而将该类进行改写，直接调用 `rand` 函数进行求取。

```c++
rand() % base
```



## 实验结论



## 实验收获

经过本次实验，本人对于 DES 的加解密机制有了充分的了解，对于密码有了进一步的掌握。同时，对于 Linux 系统上的 Socket 编程等有了进一步掌握，有助于后续的实验开发。除此之外，还学习到了 cmake 跨平台编译工具，对于日后项目开发有较大帮助。



## 文件组织说明

本次实验使用 cmake 进行编译组织。在根目录下有一个 `report.pdf` 为本次实验的实验报告，另有一个文件夹 `code`，存放本次实验用到的所有代码。

*  `./code/Readme.md` 为编译及运行说明
* `./code/bin/chat` 为可执行文件，直接运行即可
* `./code/build` 文件夹为编译文件夹，存放编译用的代码，与 `CMakeLists.txt` 及 `Makefile` 配合使用
* `./code/include` 文件夹存放编写的 DES 算法代码
* `./code/src` 文件夹则为主要的 cpp 代码

```shell
.
├── code
│   ├── CMakeLists.txt
│   ├── Readme.md
│   ├── bin
│   │   └── chat
│   ├── build
│   ├── include
│   │   └── DES.hpp
│   └── src
│       ├── CMakeLists.txt
│       └── main.cpp
└── report.pdf
```



## 实验参考

本次实验除参考下发的实验文档外，还参考了如下教程：

[https://blog.csdn.net/weixin_61823031/article/details/123053269](https://blog.csdn.net/weixin_61823031/article/details/123053269)
[https://zhuanlan.zhihu.com/p/315795886](https://zhuanlan.zhihu.com/p/315795886)
[https://github.com/Drummerboy458/DES-](https://github.com/Drummerboy458/DES-)
[https://blog.csdn.net/baiye1203/article/details/110623598](https://blog.csdn.net/baiye1203/article/details/110623598)
[https://www.iteye.com/resource/lzq824912291-2491506](https://www.iteye.com/resource/lzq824912291-2491506)
[https://github.com/KuGmonkey/TCP_DES](https://github.com/KuGmonkey/TCP_DES)
[https://github.com/OREOo-o/Des-encryption-for-TCP-chat](https://github.com/OREOo-o/Des-encryption-for-TCP-chat)
[https://blog.51cto.com/u_15169172/4859590](https://blog.51cto.com/u_15169172/4859590)
