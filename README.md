# 节点订阅转换工具：从安装到使用

这个工具用来把订阅文件转换成 Clash/Mihomo 或 v2rayN 能用的格式。

最推荐的用法是双击 `main.bat`，按菜单操作。不会命令行也可以用。

## 你需要准备什么

1. Python 3

2. 安装依赖

   ```bat
   pip install pyyaml
   ```

3. 本工具目录里的两个文件：

   - `main.bat`：菜单入口，推荐使用。
   - `main.py`：实际转换程序，不需要手动打开。

### 最简单方式：

1. 双击 `main.bat`。
2. 看到主菜单后，输入 `1` 进入单次转换。
3. 选择输出目标：
   - `1`：Clash / Mihomo，兼容性最好，推荐优先选这个。
   - `2`：v2rayN，生成 v2rayN 订阅。
   - `3`：Advanced，高级导出，里面有 base64 和 links。
4. 输入订阅文件路径，也可以直接把文件拖进窗口。
5. 确认页面会显示输入文件、输出文件和本地订阅链接。
6. 输入 `Y` 开始转换。

转换成功后，输出文件会在输入文件同一个文件夹里：

| 目标 | 输出文件 |
| --- | --- |
| Clash / Mihomo | `sub.yaml` |
| v2rayN | `sub.txt` |
| base64 / links | `sub.txt` |

## 该选 Clash 还是 v2rayN

优先选 `Clash / Mihomo`，因为它会尽量保留原始 Clash 节点字段，兼容性最好。

如果你的客户端是 v2rayN，再选 `v2rayN`。

注意：不是所有 Clash 节点都能转换成 v2rayN 分享链接。比如 HTTP、Mieru 等节点没有统一通用的分享链接格式，导出 v2rayN 时可能会显示 `skip export`。这不是程序崩溃，而是该类型不适合强制转换成 v2rayN 链接。

## 本地订阅服务怎么用

双击 `main.bat` 后，在主菜单直接按 Enter，会启动本地订阅服务。

默认地址是：

```text
http://127.0.0.1:25500/
```

常用订阅链接示例：

```text
http://127.0.0.1:25500/sub?target=clash&url=你的订阅文件或远程订阅地址
http://127.0.0.1:25500/sub?target=v2ray&url=你的订阅文件或远程订阅地址
```

如果是本地文件路径，路径里的 `C:\`、空格、中文等字符需要 URL 编码。不会编码也没关系，`main.bat` 的转换确认页会自动显示已经编码好的订阅链接，可以直接复制。

服务模式适合这种场景：

- 你想让 Clash 或 v2rayN 直接订阅本地转换结果。
- 你不想每次手动生成文件再导入客户端。

停止服务：在服务窗口按 `Ctrl + C`。

## 命令行用法

转换为 Clash：

```bat
python main.py convert C:\path\sub.yaml --to clash
```

转换为 v2rayN：

```bat
python main.py convert C:\path\sub.yaml --to v2ray
```

指定输出文件：

```bat
python main.py convert C:\path\sub.yaml --to clash -o C:\path\out.yaml
```

启动服务：

```bat
python main.py serve --host 127.0.0.1 --port 25500
```

固定一个默认来源，固定来源后，订阅链接可以简化

```text
python main.py serve --src "C:\path\sub.yaml"

http://127.0.0.1:25500/sub?target=clash
http://127.0.0.1:25500/sub?target=v2ray
```

## 支持什么输入

支持这些输入：

- Clash / Mihomo YAML，读取里面的 `proxies`。
- v2rayN / v2ray base64 订阅。
- 明文分享链接列表，每行一个链接。

常见协议包括：

- VLESS
- VMess
- Trojan
- Shadowsocks
- Socks
- HTTP
- Mieru
- Hysteria / Hysteria2

## 常见问题

### 双击 main.bat 一闪而过

通常是 Python 没装好，或者没有勾选 `Add python.exe to PATH`。

先打开 CMD，输入：

```bat
python --version
```

如果没有版本号，重新安装 Python，并勾选 PATH。

### 提示 Missing dependency PyYAML

说明缺少依赖。运行：

```bat
pip install pyyaml
```

或者：

```bat
python -m pip install pyyaml
```

### v2rayN 输出时出现 skip export

这是正常提示，表示某些节点无法表示成通用分享链接。

解决办法：

- 想最大兼容，改选 `Clash / Mihomo`。
- 只有确实需要导入 v2rayN 时，再选 `v2rayN`。

### Clash 输出为什么只有 proxies

当前 `target=clash` 输出的是节点列表：

```yaml
proxies:
  - name: example
    type: ...
```

它不是完整 Clash 配置，不会自动生成 `rules`、`proxy-groups`、`dns` 等完整配置。适合把节点交给支持订阅的客户端继续处理。

