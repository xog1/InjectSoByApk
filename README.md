# InjectSoByApk

一个用于将 `.so` 库注入到 APK 安装包中的 Python 工具，支持自动解包、依赖注入、重新打包和签名。

## 项目简介

本项目的核心逻辑在 `__init__.py` 中，提供了 `inject_and_sign()` 函数，可用于：

- 解包 APK
- 读取目标架构目录（如 `lib/arm64-v8a`, `lib/armeabi-v7a`）
- 复制并注入指定的 `.so` 文件
- 修改目标 `.so` 的 `NEEDED` 依赖列表
- 重新打包 APK
- 使用 `uber-apk-signer` 对 APK 进行签名与对齐

它适用于需要在 APK 中添加特定原生依赖，或在 Android 应用中嵌入 Hook/加载库的场景。

## 目录结构

```text
InjectSoByApk/
├── __init__.py              # 核心脚本：自动化注入与签名
├── apktool.jar              # APK 解包/重打包工具
├── uber-apk-signer.jar      # APK 签名工具
├── pyproject.toml           # Python 项目配置
├── uv.lock                  # uv 锁文件
├── README.md                # 项目说明文档
└── ...