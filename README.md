# Safetasklist

## 简介 / Introduction

**Safetasklist** 是一款旨在方便、快速列出没有加载部分已知EDR（如 Checkpoint, SentinelOne, CrowdStrike, Qianxin TianQing, Trellix, Bitdefender 等）DLL的进程的工具。该工具适用于红队任务，帮助红队成员筛选可能不被监控的进程。工具会根据进程类型（.NET 和 PE）进行分类，并排除已知的黑名单进程，最终推荐较为OPSEC的进程。

该工具具有以下功能：

- 快速列出进程，并判断是否加载了特定的EDR DLL。
- 分析进程类型：.NET 进程和 PE 进程。
- 排除已知的系统和黑名单进程，确保检测结果更加精确。
- 推荐较为OPSEC的进程。
- 支持扩展和更新进程及DLL列表，欢迎用户提交新的进程和DLL以供更新。

**Safetasklist** is a tool designed to quickly list processes that do not load certain known EDR DLLs (e.g., Checkpoint, SentinelOne, CrowdStrike, Qianxin TianQing, Trellix, Bitdefender). The tool is useful for red team operations, helping red team members identify processes that may be less monitored. It categorizes processes as either .NET or PE type, excludes known blacklist processes, and ultimately recommends processes that are more OPSEC-friendly.

Key features of the tool include:

- Quickly lists processes and checks if specific EDR DLLs are loaded.
- Categorizes processes into .NET and PE types.
- Excludes known system and blacklist processes for more accurate results.
- Recommends more OPSEC-friendly processes.
- Supports expansion and updates to process and DLL lists. Contributions are welcome!

## 使用说明 / Usage

1. **下载 / Download**: 从 [GitHub Releases](https://github.com/kyxiaxiang/Safetasklist/releases) 下载最新版本。
2. **编译 / Compile**: 使用 CSC 命令编译源码。可以使用 CS 内存加载.NET，推荐使用以下项目：
   - [PatchlessInlineExecute-Assembly](https://github.com/VoldeSec/PatchlessInlineExecute-Assembly)
   - [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
3. **运行 / Run**: 运行工具并查看输出结果，其中包含了符合条件的进程列表。
4. **提交更新 / Submit Updates**: 如果您有新的进程或DLL信息，欢迎向本项目提交更新，帮助工具持续改进。

1. **Download**: Download the latest version from [GitHub Releases](https://github.com/kyxiaxiang/Safetasklist/releases).
2. **Compile**: Compile the source code using the CSC command. You can load .NET in memory using CS, and it's recommended to use:
   - [PatchlessInlineExecute-Assembly](https://github.com/VoldeSec/PatchlessInlineExecute-Assembly)
   - [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
3. **Run**: Run the tool and check the output, which includes a list of processes that meet the criteria.
4. **Submit Updates**: If you have new process or DLL information, feel free to contribute and submit updates to improve the tool.

## 支持的EDR / Supported EDRs

当前支持以下EDR产品的DLL监测：

- Checkpoint
- SentinelOne
- CrowdStrike
- Qianxin TianQing (奇安信天擎)
- Trellix
- Bitdefender

后续版本将增加更多支持的EDR，敬请期待。

Currently, the tool supports monitoring DLLs from the following EDR products:

- Checkpoint
- SentinelOne
- CrowdStrike
- Qianxin TianQing (奇安信天擎)
- Trellix
- Bitdefender

More EDRs will be added in future versions, stay tuned.



![](https://github.com/kyxiaxiang/Safetasklist/blob/main/png/CS-01.png?raw=true)

![](https://github.com/kyxiaxiang/Safetasklist/blob/main/png/CS-02.png?raw=true)

![](https://github.com/kyxiaxiang/Safetasklist/blob/main/png/S1-01.png?raw=true)

![](https://github.com/kyxiaxiang/Safetasklist/blob/main/png/S1-02.png?raw=true)

在演示中，SentinelOne开启了完整的激进模式，几乎所有的进程都被监控。因此，可以看到推荐的OPSEC进程列表为空。但红队操作员仍然可以观察到，系统中存在三个可以使用的进程。然而，在加载网络通讯模块时，操作员需要格外小心，以避免被EDR监控到。

In the demo, SentinelOne is configured with full aggressive mode, where almost all processes are monitored. As a result, the recommended OPSEC process list is empty. However, red team operators can still observe that three processes are available for use. Care should be taken when loading network communication modules to avoid detection by the EDR.

## 特性 / Features

- 自动检测没有加载已知EDR DLL的进程。
- 分类列出 `.NET` 和 `PE` 类型的进程。
- 排除已知的黑名单进程，减少干扰。
- 推荐较为OPSEC的进程。
- 易于扩展和定制，支持用户提交新的进程和DLL信息。

- Automatically detects processes that do not load known EDR DLLs.
- Categorizes processes into `.NET` and `PE` types.
- Excludes known blacklist processes to reduce noise.
- Recommends more OPSEC-friendly processes.
- Easy to extend and customize, supporting contributions of new process and DLL information.

## 贡献 / Contributing

欢迎大家为这个项目贡献新的进程和DLL列表，或者提供其他的改进意见。请通过提交Pull Request或在Issues中提出您的建议。

Contributions of new process and DLL lists, or suggestions for improvements, are welcome! Please submit Pull Requests or open Issues to share your ideas.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
