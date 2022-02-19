根据不同的dns服务器获取某一 host 的所有的 ip，并通过 tcp 或者 http 测试延迟，获取该 host 最快的ip。

### 安装
```shell
git clone https://github.com/llklkl/hostdig.git

cd hostdig
go build -o hostdig main.go
```

### 配置
dns_list 文件格式为每行一个 dns 的ip，支持读取本地文件或者网络文件。
hosts 文件格式为每行一个 host。

配置文件 example:
```yaml
dns_list:
  - type: file
    path: /path/to/your/dns/list/file
  - type: remote
    path: http://example.com/dnslist.txt
hosts:
  - path: /path/to/your/hosts
```

### 使用方式

一些可行的使用方式
+ **直接输出到文件**
```shell
hostdig -c ./config.yaml -o hosts -q
```

+ **替换更新文件**
```shell
hostdig -c ./config.yaml -o /etc/hosts -q -r
```

+ **开启一个服务器，通过接口获取hosts，并每小时更新一次**
```shell
hostdig -c ./config.yaml -l=:8080 --period=3600 -q
```

该方式可以配合 `SwitchHosts` 软件使用。可以通过 `curl -XGET http://127.0.0.1:8080` 获取hosts。在更新hosts文件之后，也可以使用 `curl -XGET http://127.0.0.1:8080/refresh` 强制更新。


更多的使用方式可以通过 `hostdig -h` 获取帮助。