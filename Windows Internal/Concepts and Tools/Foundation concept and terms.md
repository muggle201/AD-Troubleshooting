# Windows API

The windows application programing interface (API) is the user-mode system programing interface to the Windows OS.

Win32 API



> How to program the Windows base API is in the book ***Windows via C/C++***.



## Windows API flavors

劣势：

- 缺乏名称一致性
- 缺乏Logical groupings



因此一些新的API使用了不同的API机制：Component Object Model (COM)



COM最初创建时，用于使得Office应用能在不同文档中传递并交换数据。这种能力称为Object Linking and Embedding (OLE)。OLE在最初使用的是古老的Windows messaging机制，Dynamic Data Exchange (DDE)。



COM基于两大基本法则：

- Client与Object（有时称作COM server objects）
- 动态加载组件而非静态链接至client



## The .NET Framework

Two major components:

- **The Common Language Runtime (CLR)** 
- **The .NET Framework Class Library (FCL)**



# Services, Functions, and Routines

