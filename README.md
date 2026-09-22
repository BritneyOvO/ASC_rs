# ASC

ASC 的 Rust 重写。它是给自动化分析和移动安全研究用的 Android 反编译前端：不预先把整个 APK 做成交叉引用数据库，而是把 ZIP 里的 DEX 当成只读数据，用到哪一段再解压、再查询。

上游项目：<https://github.com/MG1937/ASC>

## 命令

```text
asc getclass app.apk Lcom/poc/Main; -o Main.java
asc getclass app.apk com.poc.Main --threads 16
asc listclass app.apk --prefix com.poc -o classes.txt
asc getmanifest app.apk -o AndroidManifest.xml
asc findrefs app.apk string token -o string_refs.txt
asc findrefs app.apk type com.poc.Main
asc findrefs app.apk method onCreate --class com.poc.Main
asc findrefs app.apk method notify --class MainActivity --fuzzy-class
asc findrefs app.apk field apiKey
```

`listclass` 按 DEX 条目和 `class_def` 的顺序输出 Dalvik 描述符，一行一个。`--prefix com.poc` 会规范成 `Lcom/poc`。`findrefs` 的 string/type，以及不带精确类名的 method/field 名字，按正则匹配字符串表（`.` 匹配任意字节，和上游一样）。

## 构建

需要 Rust 1.74 或更新版本。

```sh
cargo test
cargo build --release
./target/release/asc --help
```

## 和上游 Python 版的差别

- 引用搜索、类列表、DEX 041 容器和 ZIP 中央目录扫描沿用同一套规则：16 字节指令桶、指令边界校验、按需 inflate。
- `getclass` 用原生字节码提升打印 Java 签名和方法体，不调用 Androguard。类结构、方法签名和常量可以直接读；控制流不会被重构成完整的 Java AST。
- 多个 DEX 同时命中时，结果按压缩后体积排序，避免多线程完成顺序抖动。
- 不提供 GUI。上游 Tk 界面和源码回写都没有移植。

## 许可

Apache License 2.0。本仓库是 <https://github.com/MG1937/ASC> 的衍生作品，见 `NOTICE`。
