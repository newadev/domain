# 域名扫描器

一个强大的域名可用性检查工具，使用 Go 语言编写。

## 项目来源

本项目基于 [https://github.com/xuemian168/domain-scanner](https://github.com/xuemian168/domain-scanner) 进行修改和优化。

### 原项目致谢

感谢原作者 [xuemian168](https://github.com/xuemian168) 提供的优秀基础代码。本项目在原有功能基础上进行了架构重构和功能增强，保持了与原项目的兼容性。

### 更新日志

#### v1.3.2 (2025-01-28)
- 🏗️ **架构重构**: 采用模块化设计，代码组织更清晰
- 🎯 **检测准确性提升**: 特别优化了.de域名的WHOIS检测
- 🔄 **重试机制改进**: 增加重试次数和智能等待，提高GitHub Actions稳定性
- 📊 **调试功能增强**: 新增详细的verbose模式日志
- ⚡ **性能优化**: 流式域名生成，降低内存占用
- 🛡️ **安全性提升**: 正则表达式ReDoS防护
- 📦 **二进制文件更新**: 重新编译，包含所有最新改进

### 主要改进

- 🏗️ **模块化架构重构**：采用清晰的 `internal/` 包结构，提高代码可维护性
- 🎯 **增强域名检测准确性**：优化WHOIS解析，特别针对DENIC (.de域名) 的检测
- 🔄 **改进重试机制**：增加重试次数和智能等待时间，提高GitHub Actions环境稳定性
- 📊 **详细调试日志**：在verbose模式下提供完整的检测过程信息
- ⚡ **流式域名生成**：优化内存使用，支持大规模域名扫描
- 🛡️ **正则表达式安全**：防止ReDoS攻击，支持超时保护
- 🔧 **GitHub Actions优化**：调整并发参数，提高云环境检测准确性

### 版本信息

- **当前版本**: v1.3.2 (2025-01-28)
- **Go版本要求**: 1.22+
- **架构**: 模块化设计，支持跨平台编译
- **二进制文件**: 已更新至最新版本，包含所有架构改进

## 快速开始

### 方式一：使用预编译二进制文件

项目根目录包含最新编译的二进制文件 `domain-scanner`（适用于当前平台）：

```bash
# 直接使用当前平台的二进制文件
./domain-scanner [选项]

# 查看帮助信息
./domain-scanner -h

# 示例：扫描3位.de域名
./domain-scanner -l 3 -s .de -p D -workers 5
```

如需其他平台的二进制文件，可以使用下面的跨平台编译方法。

### 方式二：从源码编译

#### 环境要求
- Go 1.22 或更高版本
- Git

#### 编译步骤

```bash
# 克隆项目
git clone https://github.com/your-username/domain-scanner.git
cd domain-scanner

# 安装依赖
go mod tidy

# 编译当前平台版本
go build -o domain-scanner .

# 或编译所有平台版本
make build-all

# 运行
./domain-scanner [选项]
```

#### 跨平台编译

```bash
# Linux x64
GOOS=linux GOARCH=amd64 go build -o domain-scanner-linux-amd64 .

# Windows x64
GOOS=windows GOARCH=amd64 go build -o domain-scanner-windows-amd64.exe .

# macOS x64
GOOS=darwin GOARCH=amd64 go build -o domain-scanner-darwin-amd64 .

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o domain-scanner-darwin-arm64 .
```

### 方式三：直接运行源码

```bash
go run main.go [选项]
```

### 配置文件结构

所有配置文件都位于 `config/` 目录下：

- `config.toml` - 主配置文件
- `regex-examples.toml` - 正则表达式示例配置
- `config_batch_*.toml` - 批量处理配置文件

### 配置文件示例

#### 使用默认配置
```bash
go run main.go
```

#### 使用自定义配置
```bash
go run main.go -config config/myconfig.toml
```

## GitHub Actions 工作流

本项目包含一个强大的 GitHub Actions 工作流，支持批量域名扫描自动化。

### 工作流特性

#### 🚀 批量扫描自动化
- **并行处理**：自动创建多个并发任务，每个字母一个批次
- **灵活配置**：支持自定义域名后缀、长度、模式等参数
- **结果汇总**：自动合并所有批次的结果并生成汇总报告
- **超时保护**：每个任务6小时超时，避免无限运行

### 使用方法

#### 1. 手动触发工作流

在 GitHub 仓库中：
1. 进入 **Actions** 标签页
2. 选择 **Batch Domain Scanner** 工作流
3. 点击 **Run workflow** 按钮
4. 配置扫描参数：
   - **Starting batch index** (0-25): 开始的批次索引（0=A, 1=B, ...）
   - **Number of batches to run** (1-26): 运行多少个批次
   - **Domain suffix to scan**: 域名后缀（.de, .com, .net, .org, .io, .ai, .li）
   - **Domain name length** (3-6): 域名长度
   - **Domain pattern**: 域名模式（D=字母, d=数字, a=字母数字）

#### 2. 参数示例

**扫描前5个字母的4位.de域名：**
- Starting batch index: `0`
- Number of batches to run: `5`
- Domain suffix: `.de`
- Domain length: `4`
- Pattern: `D`

**扫描所有字母的3位.com域名：**
- Starting batch index: `0`
- Number of batches to run: `26`
- Domain suffix: `.com`
- Domain length: `3`
- Pattern: `D`

### 工作流架构

#### 三阶段执行流程

1. **准备阶段 (prepare)**
   - 设置 Go 环境
   - 根据用户输入生成批量配置文件
   - 创建任务矩阵，定义每个批次的参数

2. **扫描阶段 (scan)**
   - 并行运行多个批次任务
   - 每个任务独立扫描特定字母开头的域名
   - 自动上传结果文件为 GitHub Artifacts

3. **汇总阶段 (summarize)**
   - 下载所有批次的结果
   - 合并可用域名、已注册域名、特殊状态域名的结果
   - 生成汇总报告和统计信息
   - 在 workflow summary 中显示结果概览

### 输出文件

#### 各批次结果
- `domain-scan-results-batch-{letter}`: 每个字母批次的独立结果

#### 合并结果
- `domain-scan-results-combined`: 包含所有批次的合并结果文件
  - `available_domains_all.txt`: 所有可用域名
  - `registered_domains_all.txt`: 所有已注册域名
  - `special_status_domains_all.txt`: 所有特殊状态域名
  - `summary.txt`: 详细的扫描报告（已去重并确保分类互斥，包含并集总量与期望空间大小校验）

> 说明：汇总阶段会调用 `summarize_combined_results.py` 对三个文件做规范化处理：
> - 特殊状态文件仅取首列域名并去重（忽略注释与空行）。
> - 统计时保证三类互斥（已注册 = 已注册原始集合 - 特殊状态）。
> - 计算三类并集的唯一域名总量，并与理论空间大小（如 Pattern=`D` 且长度=3 时为 26^3）进行校验。

#### 特殊状态域名说明
- 存储格式：每行 `domain status reason`
- 常见状态标识（不计入“可注册”）：
  - `DROPZONE_AVAILABLE`：可通过 Identity Digital Dropzone 申请（并非公开注册）
  - `PREMIUM`：高级/溢价域名
  - `RESERVED`：注册局或注册商保留
  - `REDEMPTION_PERIOD`：赎回期
  - `PENDING_DELETE`：即将删除
  - `HOLD`：暂停/冻结（client/server hold 等）
  - `WHOIS_RATE_LIMITED`：WHOIS 限流，需人工复核
  - `CHECK_TIMEOUT`：单域名检测超时，未判定

可使用脚本将特殊域名按状态拆分输出：

```bash
python3 special_domain_processor.py

# 输出目录：
# domain-check/special/              # 按字符模式分类（AABB/ABCD 等）
# domain-check/special/by-status/    # 按状态拆分（如 PREMIUM.txt / DROPZONE_AVAILABLE.txt）
```

### 查看结果

#### 1. GitHub Artifacts
- 工作流运行完成后，结果文件会作为 Artifacts 保存
- 可以下载单独批次的结果或合并的完整结果
- Artifacts 保存90天，可随时下载

#### 2. Workflow Summary
- 在工作流页面查看自动生成的结果汇总
- 包含配置信息、统计数字和示例域名
- 无需下载文件即可快速了解扫描结果

### 注意事项

#### ⚠️ 重要提醒
- **使用限制**：GitHub Actions 有运行时间限制，请合理设置批次数量
- **资源消耗**：批量扫描会消耗大量 GitHub Actions 分钟数
- **网络策略**：频繁的 WHOIS 和 DNS 查询可能触发平台的限流
- **合规性**：请确保遵守相关域名注册商的使用条款
- **配置文件**：确保使用正确的配置文件路径，避免使用格式错误的文件名

### 稳定性与超时保护

- WHOIS 查询超时保护：单次 WHOIS 调用设置硬超时 10 秒，避免极少数情况下底层库发生卡顿。
- 单域名整体检测超时：Worker 对每个域名设置 45 秒看门狗，若超时则标记为 `CHECK_TIMEOUT` 并继续处理后续域名，避免队列阻塞导致工作流超时。
- 限流自动退避：对 WHOIS 限流或“访问受控”等返回，采用指数退避并在最后一次失败时标记 `WHOIS_RATE_LIMITED`，不将该域名计入“可注册”。

提示：上述策略显著降低“进度卡在 [x/y] 不动”导致 6 小时工作流被取消的概率。

### 重新编译二进制

在仓库根目录执行：

```bash
go build -o domain-scanner .
```

生成的可执行文件为 `./domain-scanner`，已包含特殊状态标识、超时与去重等最新改动。

#### 🔧 故障排除
- 如果任务超时，可以减少批次数量或增加延迟时间
- 如果遇到限流，可以调整并发任务数或等待一段时间后重试
- 检查工作流日志以获取详细的错误信息和执行状态
- **配置文件错误**: 如果发现 `%!s(int32=number)` 格式的文件，说明是Go格式化错误产生的无效文件，可以安全删除

### 配置文件路径

工作流中的配置文件路径已更新为：
- 批量配置文件：`config/config_batch_{letter}.toml`
- 结果输出目录：`./results/batch_{letter}/`

确保在运行工作流前，相关配置文件路径与实际文件结构一致。

## 工作流文件说明

### 📁 三个工作流文件的作用

#### 1. **go.yml** - 基础 CI/CD 工作流
- **触发条件**: 推送到 main 分支、Pull Request、Release 创建
- **主要功能**:
  - **自动构建**: 每次提交时自动编译 Go 项目
  - **运行测试**: 执行 `go test` 进行单元测试
  - **代码检查**: 运行 `golangci-lint` 进行代码质量检查
  - **自动发布**: 当创建 Git tag 时，自动使用 GoReleaser 发布新版本
- **使用状态**: ✅ **完全可用** - 所有功能都经过配置，无需额外设置

#### 2. **domain-scan.yml** - 单次域名扫描工作流
- **触发条件**: 手动触发 (workflow_dispatch)
- **主要功能**:
  - **配置扫描**: 支持选择不同的配置文件进行扫描
  - **超长运行**: 30天超时时间，适合长时间扫描任务
  - **结果处理**: 自动创建 GitHub Issue 发布扫描结果
  - **产物上传**: 将扫描结果上传为 GitHub Artifacts
- **使用状态**: ✅ **完全可用** - 配置文件路径已修复

#### 3. **batch-domain-scan.yml** - 批量域名扫描工作流
- **触发条件**: 手动触发 (workflow_dispatch)
- **主要功能**:
  - **批量并行**: 支持多个字母批次的并行扫描
  - **动态配置**: 根据用户输入自动生成批量配置文件
  - **结果汇总**: 自动合并所有批次的结果并生成汇总报告
  - **超时保护**: 每个任务6小时超时，总体限时运行
- **使用状态**: ✅ **完全可用** - 配置文件路径已修复

### 🚨 工作流可用性分析

#### ✅ 完全可用的工作流
- **go.yml**: 所有功能正常，无需修改
- **batch-domain-scan.yml**: 已修复配置文件路径问题，完全可用

## 配置文件说明

### 📂 配置文件结构解析

#### 1. **主配置文件**
- **`config/config.toml`**: 主要的域名扫描配置文件
  - 包含域名生成参数（长度、后缀、模式）
  - 扫描行为设置（延迟、并发数）
  - 输出文件配置和检测方法开关

#### 2. **批量配置文件** (26个)
- **`config/config_batch_a.toml` 到 `config/config_batch_z.toml`**: 每个字母一个配置
  - 每个文件配置特定字母开头的域名扫描
  - 例如：`config_batch_a.toml` 只扫描以 'a' 开头的域名
  - 使用正则过滤器 `^a.*` 进行域名过滤
  - 输出到独立的批次目录 `./results/batch_a/`

#### 3. **特殊配置文件**
- **`config/regex-examples.toml`**: 正则表达式过滤器示例库
  - 包含50+种域名过滤模式
  - 涵盖回文、对称模式、字母组合等
  - 提供SEO友好、品牌友好的域名过滤方案

### 🔧 配置文件的作用和用法

#### 主配置文件 (config.toml)
```bash
# 使用主配置文件
go run main.go -config config/config.toml

# 或者使用默认配置（自动读取 config/config.toml）
go run main.go
```

#### 批量配置文件 (config_batch_*.toml)
```bash
# 扫描所有a开头的4位.de域名
go run main.go -config config/config_batch_a.toml

# 扫描所有b开头的域名
go run main.go -config config/config_batch_b.toml
```

#### 正则表达式示例 (regex-examples.toml)
```bash
# 复制示例中的正则表达式到主配置文件
# 例如使用AABB模式
sed 's/regex_filter_aabb = "^([a-z])\\\\1([a-z])\\\\2$"/regex_filter = "^([a-z])\\\\1([a-z])\\\\2"/' config/regex-examples.toml >> temp_config.toml
```

### 🎯 配置文件设计理念

#### 1. **模块化设计**
- 主配置用于日常使用
- 批量配置用于大规模扫描
- 示例配置用于学习和参考

#### 2. **灵活组合**
- 可以手动创建任意数量的配置文件
- 支持不同的域名后缀、长度、模式组合
- 正则表达式可以自由组合和定制

#### 3. **批量处理优化**
- 每个字母独立配置，避免单次任务过大
- 并行处理多个批次，提高扫描效率
- 结果文件分离，便于管理和分析

#### 4. **实用导向**
- 提供常见的域名过滤模式
- 包含SEO和品牌友好的配置建议
- 提供调试和测试的最佳实践

### 📊 配置文件统计

| 类型 | 文件数量 | 主要用途 | 示例 |
|------|----------|----------|------|
| 主配置 | 1 | 日常扫描 | config.toml |
| 批量配置 | 26 | 字母批量扫描 | config_batch_a.toml |
| 示例配置 | 1 | 正则表达式参考 | regex-examples.toml |

### 🔄 工作流与配置文件关系

#### go.yml + config.toml
- 每次提交时验证主配置文件的有效性
- 确保主程序能正常编译和运行

#### domain-scan.yml + config.toml
- 手动触发单次域名扫描
- 使用主配置文件进行扫描任务

#### batch-domain-scan.yml + config_batch_*.toml
- 手动触发批量域名扫描
- 动态生成或使用预定义的批量配置文件
- 并行处理多个配置文件

### 💡 使用建议

#### 1. **日常使用**
- 使用 `config.toml` 进行常规扫描
- 修改主配置文件中的参数满足需求

#### 2. **大规模扫描**
- 使用批量配置文件进行并行扫描
- 可以同时运行多个批次，每个批次处理不同的字母

#### 3. **特殊需求**
- 参考 `regex-examples.toml` 中的正则表达式
- 复制需要的模式到主配置文件中使用

#### 4. **工作流选择**
- 代码质量检查：使用 **go.yml**（自动触发）
- 单次扫描：使用 **domain-scan.yml**（完全可用）
- 批量扫描：使用 **batch-domain-scan.yml**（完全可用）

## 基本选项

- `-l int`: 域名长度（默认：3）
- `-s string`: 域名后缀（默认：.li）
- `-p string`: 域名模式：
  - `d`: 纯数字（例如：123.li）
  - `D`: 纯字母（例如：abc.li）
  - `a`: 字母数字混合（例如：a1b.li）
- `-workers int`: 并发工作线程数（默认：10）
- `-delay int`: 查询间隔（毫秒）（默认：1000）
- `-config string`: 配置文件路径（默认：config/config.toml）

## 扫描多级域名（如 aa.bbb.cc）

工具支持把“后缀”视为固定部分，因此可以直接把多级后缀写进 `-s` 即可。例如需要扫描形如 `aa.bbb.cc` 的域名（可变的是最左侧的 `aa`），把后缀设置为 `.bbb.cc`，把长度设置为 2：

```bash
# 纯字母（aa、ab、...、zz）
go run main.go -l 2 -s .bbb.cc -p D -workers 15 -delay 500

# 纯数字（00、01、...、99）
go run main.go -l 2 -s .bbb.cc -p d

# 字母数字（a0、a1、...、z9）
go run main.go -l 2 -s .bbb.cc -p a
```

同样也可以在配置文件中设置：

```toml
[domain]
length = 2
suffix = ".bbb.cc"
pattern = "D" # D=字母, d=数字, a=字母数字
```

提示：`suffix` 只要以点开头即可，允许像 `.bbb.cc` 这样的多级后缀。

### 关于三级（及以上）“可用性”的说明

- 本工具默认通过 DNS/WHOIS/SSL 迹象综合判断“是否已被注册”。WHOIS 通常只对可注册的二级域名（如 `bbb.cc`）有意义，像 `aa.bbb.cc` 这样的子域名并不存在“注册可用性”的概念。
- 如果你的目标是“枚举并发现已存在的子域名”，建议启用 DNS 检查、关闭 WHOIS 检查，以 DNS 存在性为准：

```toml
[scanner.methods]
dns_check = true
whois_check = false
ssl_check = false
```

这样会以 `A/MX/TXT/CNAME` 等记录是否存在来判断子域是否“存在/活跃”。

> 如果需要使用字典进行更真实的子域枚举（如常见的 `www/mail/api` 等），可以把正则或长度/模式调整为更贴合的集合，或配合外部字典脚本批量生成前缀，再通过本工具进行 DNS 解析验证。
