# <center>**网络安全技术实验报告**</center>

<center>Lab4 端口扫描器的设计与实现</center>

<center> 网络空间安全学院 信息安全专业</center>

<center> 2112492 刘修铭 1027</center>

## 实验要求





## 实验目标 

1. 掌握端口扫描器的基本设计方法。
2. 理解 ping 程序，TCP connect 扫描，TCP SYN 扫描，TCP FIN 扫描以及 UDP 扫描的工作原理。
3. 熟练掌握 Linux 环境下的套接字编程技术。
4. 掌握 Linux 环境下多线程编程的基本方法



## 实验内容

1. 编写端口扫描程序，提供 TCP connect 扫描，TCP SYN 扫描，TCP FIN 扫描以及 UDP 扫描 4 种基本扫描方式。
2. 设计并实现 ping 程序，探测目标主机是否可达。



## 实验步骤





## 实验结论



<img src="./report.pic/image-20240509114528195.png" alt="image-20240509114528195" style="zoom:50%;" />



<img src="./report.pic/image-20240509114541902.png" alt="image-20240509114541902" style="zoom:50%;" />



<img src="./report.pic/image-20240509114803679.png" alt="image-20240509114803679" style="zoom:50%;" />



<img src="./report.pic/image-20240509114835523.png" alt="image-20240509114835523" style="zoom:50%;" />



<img src="./report.pic/image-20240509114625260.png" alt="image-20240509114625260" style="zoom:50%;" />





## 实验遇到的问题及其解决方法





## 实验收获

对于端口扫描器这一网络安全检测工具有了初步的认识，对于 Linux 上的套接字编程技术有了更多了解，对于 Cmake 编译组件充分掌握。



## 文件组织说明

本次实验使用 cmake 进行编译组织。在根目录下有一个 `report.pdf` 为本次实验的实验报告，另有一个文件夹 `code`，存放本次实验用到的所有代码。

*  `./code/Readme.md` 为编译及运行说明
* `./code/bin/Scanner` 为可执行文件，直接运行即可
* `./code/include` 文件夹存放编写的代码头文件
* `./code/Makefile` 为编译文件，用于对程序进行编译处理
* `./code/src` 文件夹则为主要的 cpp 代码

```shell
.
├── code
│   ├── Readme.md
│   ├── bin
│   │   └── Scanner
│   ├── include
│   │   ├── defs.h
│   │   ├── Scanner.h
│   │   ├── TCPConnectScan.hpp
│   │   ├── TCPFINScan.hpp
│   │   ├── TCPSYNScan.hpp
│   │   └── UDPScan.hpp
│   ├── Makefile
│   └── src
│       └── main.cpp
└── report.pdf
```



## 实验参考

吴功宜主编.网络安全高级软件编程技术.清华大学出版社.2010

