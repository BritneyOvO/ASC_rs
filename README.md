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

`listclass` 按 DEX 条目和 `class_def` 的顺序输出 Dalvik 描述符，一行一个。`--prefix com.poc` 会规范成 `Lcom/poc`。`findrefs` 的 string/type 在每条字符串内容上做正则搜索（`.` 匹配任意字节，可以命中字符串中间）。不带 `--class` 的 method/field 名字必须匹配整个简单名；带精确 `--class` 时名字按字面量完全相等。`--fuzzy-class` 的类名仍是子串正则。

同名类在 `getclass` 和 `dump` 里按运行时顺序保留：`classes.dex`、`classes2.dex`、`classes10.dex`，其余根目录 DEX 按中央目录顺序排在后面。ZIP 读取支持 store、deflate、数据描述符和 ZIP64。中央目录里的 CRC 非 0 时会校验解压结果；CRC 为 0 的条目仍然读取。

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
- `findrefs` 同时命中多个 DEX 时，结果按压缩后体积排序，避免多线程完成顺序抖动。

## 许可

Apache License 2.0。本仓库是 <https://github.com/MG1937/ASC> 的衍生作品，见 `NOTICE`。
