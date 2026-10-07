# ASC

ASC 的 Rust 重写。它是给自动化分析和移动安全研究用的 Android 反编译前端：不预先把整个 APK 做成交叉引用数据库，而是把 ZIP 里的 DEX 当成只读数据，用到哪一段再解压、再查询。

上游项目：<https://github.com/MG1937/ASC>

## 命令

```text
asc getclass app.apk Lcom/poc/Main; -o Main.java
asc getclass app.apk com.poc.Main --threads 16
asc getclass app.apk com.poc.Main --engine smali
asc listclass app.apk --prefix com.poc -o classes.txt
asc getmanifest app.apk -o AndroidManifest.xml
asc findrefs app.apk string token -o string_refs.txt
asc findrefs app.apk type com.poc.Main
asc findrefs app.apk method onCreate --class com.poc.Main
asc findrefs app.apk method notify --class MainActivity --fuzzy-class
asc findrefs app.apk field apiKey
```

`getclass` 和 `dump` 默认用 [ddc](https://github.com/ejfkdev/ddc) 把方法体收成带控制流的 Java。`--engine smali` 输出 baksmali 文本，指令名和寄存器都保留。`listclass`、`findrefs`、清单，以及 HAP / ABC，不走 ddc。

`listclass` 按 DEX 条目和 `class_def` 的顺序输出 Dalvik 描述符，一行一个。`--prefix com.poc` 会规范成 `Lcom/poc`；ABC 侧四种写法（`com.poc`、`Lcom.poc`、`com/poc`、`Lcom/poc`）等价，点号和斜杠都当包分隔符。`findrefs` 的 string/type 在每条字符串内容上做正则搜索（`.` 匹配任意字节，可以命中字符串中间）。不带 `--class` 的 method/field 名字必须匹配整个简单名；带精确 `--class` 时名字按字面量完全相等。`--fuzzy-class` 的类名是子串，但按字面量匹配（内部类的 `$` 不再是正则元字符），只把点号当包分隔符。

资源取值按配置挑选：真正的默认配置（mcc/mnc、locale、密度、uiMode、sdkVersion 等全部限定符都为空）优先于任何限定配置，无论它出现在文件里的先后。字符串资源一律按字符串引用写回代码，即使内容看起来像数字或颜色。

中央目录里任何一条记录读不通都按错误上报，不再静默截断条目列表；`find_eocd` 会核对注释长度，压缩包注释里出现 `PK\x05\x06` 不会被误判。单个条目解压上限为 1 GiB，并且不会超过中央目录声明的解压大小；声明为 0 时按 deflate 的 1032 倍膨胀率上界收紧。HAP 的 `dump` 逐成员容错：读不通的 `.abc` 会告警并计入 `errors`，其余成员照常导出。

`PANDA` 开头的 `.abc` 按方舟文件头现查类名、成员和字面量字符串，不建全量索引。HAP 里的代码在 `ets/modules.abc` 和其它 `*.abc`。`getmanifest` 读模块配置 `module.json`（没有则读 `config.json`）和包级 `pack.info`，并把 `$string:`、`$media:`、`$profile:` 换成 `resources/` 里的值。APK 清单里的 `@string/`、`@mipmap/` 和 `@0x7f......` 会换成 `resources.arsc` 或 `res/` 里的实际值。同一张表也写回 DEX：`getclass` 和 `dump` 里的常量、`R$type;->name`、字符串中的 `@string/`，以及 `findrefs` 命中的字符串和字段，都换成解析后的值。HAP 里 ABC 的类文本和字面量同样把 `$string:`、`$media:`、`$profile:` 换成资源值，所以按解析后的文本搜索也能命中。单独打开的 `.dex` 和 `.abc` 没有随包资源表，原文保持不动。`listclass`、`getclass`、`findrefs`、`getmanifest` 和 `dump` 可以直接读 HAP。

同名类在 `getclass` 和 `dump` 里按运行时顺序保留：`classes.dex`、`classes2.dex`、`classes10.dex`，其余根目录 DEX 按中央目录顺序排在后面。Android App Bundle 里的代码在 `<module>/dex/*.dex`，清单在 `base/manifest/AndroidManifest.xml`（aapt2 protobuf XML）；同名类先保留 `base` 模块，再保留其它模块。ZIP 读取支持 store、deflate、数据描述符和 ZIP64。中央目录里的 CRC 非 0 时会核对解压结果，不一致时在标准错误告警并继续读取；CRC 为 0 的条目不核对。

## 构建

需要 Rust 1.74 或更新版本。

```sh
cargo test
cargo build --release
./target/release/asc --help
```

## 和上游 Python 版的差别

- 引用搜索、类列表、DEX 041 容器和 ZIP 中央目录扫描沿用同一套规则：16 字节指令桶、指令边界校验、按需 inflate。
- `getclass` 和 `dump` 默认调用 ddc（`jdc-core`）重构控制流。`--engine smali` 打印标准 smali，不把指令提升成 Java 语句。
- `findrefs` 同时命中多个 DEX 时，结果按压缩后体积排序，避免多线程完成顺序抖动。

## 许可

Apache License 2.0。本仓库是 <https://github.com/MG1937/ASC> 的衍生作品，见 `NOTICE`。
