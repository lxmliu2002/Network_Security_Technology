# <center>**网络安全技术实验报告**</center>

<center>Lab3 基于 MD5 算法的文件完整性校验程序</center>

<center> 网络空间安全学院 信息安全专业</center>

<center> 2112492 刘修铭 1027</center>

## 实验要求





## 实验目标 





## 实验内容





## 实验步骤





## 实验遇到的问题及其解决方法





## 实验结论



<img src="./report.pic/65d46677328509738270b3319c25a26.png" alt="65d46677328509738270b3319c25a26" style="zoom:50%;" />



<img src="./report.pic/27dcf9d55e72c435df3ca0b3df78cb5.png" alt="27dcf9d55e72c435df3ca0b3df78cb5" style="zoom:50%;" />



<img src="./report.pic/7f577d124d6c23acfe470dd4047acfc.png" alt="7f577d124d6c23acfe470dd4047acfc" style="zoom:50%;" />



<img src="./report.pic/78c19c7148eccf750a2699e99ce993a.png" alt="78c19c7148eccf750a2699e99ce993a" style="zoom: 43%;" />



<img src="./report.pic/1300f0ed40de4157dfa7db87da5d88a.png" alt="1300f0ed40de4157dfa7db87da5d88a" style="zoom:50%;" />



<img src="./report.pic/dbd35e5848645edb8d9a0452c11b155.png" alt="dbd35e5848645edb8d9a0452c11b155" style="zoom:50%;" />



<img src="./report.pic/ad5d44a3a6d5578a9786661a776b315.png" alt="ad5d44a3a6d5578a9786661a776b315" style="zoom:50%;" />



<img src="./report.pic/668445f88211f92924be738012d6546.png" alt="668445f88211f92924be738012d6546" style="zoom:50%;" />



## 实验收获





## 文件组织说明

本次实验使用 cmake 进行编译组织。在根目录下有一个 `report.pdf` 为本次实验的实验报告，另有一个文件夹 `code`，存放本次实验用到的所有代码。

*  `./code/Readme.md` 为编译及运行说明
* `./code/bin/MD5` 为可执行文件，直接运行即可
* `./code/build` 文件夹为编译文件夹，存放编译用的代码，与 `CMakeLists.txt` 及 `Makefile` 配合使用
* `./code/include` 文件夹存放编写的 DES 算法代码
* `./code/src` 文件夹则为主要的 cpp 代码

```shell
.
├── code
│   ├── CMakeLists.txt
│   ├── Readme.md
│   ├── bin
│   │   └── MD5
│   ├── build
│   ├── include
│   │   ├── DES.hpp
│   │   └── RSA.hpp
│   └── src
│       ├── CMakeLists.txt
│       └── main.cpp
└── report.pdf
```



## 实验参考

吴功宜主编.网络安全高级软件编程技术.清华大学出版社.2010

[https://zhuanlan.zhihu.com/p/351883327](https://zhuanlan.zhihu.com/p/351883327)
