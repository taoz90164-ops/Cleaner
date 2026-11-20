# 分类规则 v1

扫描器与执行器共用 DiskCore.cs，不允许 Agent 用自由文本替代分类。优先级：保护与链接 → 明确垃圾范围 → 软件登记/已知软件映射 → 个人资产 → 其他。文件只计入一个占用实体；清理卡片可以是该实体的子范围，但合计预计释放要扣重。

## 放心清理

| kind | 固定栏目 | 正面识别 | 排除/执行约束 |
|---|---|---|---|
| temp | 软件临时碎片 | 实际 TEMP 或用户 Local/Temp 中超过7天的文件 | 恢复、自动保存、未完成下载，近期或混合目录不可整体加入 |
| package | 安装与更新包 | MSI复合文件格式；EXE的PE格式配合安装器元数据或已知更新位置；更新目录中可辨认的安装压缩包 | 不只凭扩展名或 setup 名称；排除卸载器、软件主程序、便携程序、系统及共享组件仓库 |
| logs | 旧日志与故障记录 | 已知应用 logs/crash位置中的历史 .log/.dmp/.mdmp/.hdmp/.etl/.txt，超过7天 | 当前日志、业务文档、备份；不全盘搜索名字含log的文件夹 |
| browsercache | 浏览器网页缓存 | Chrome/Edge/Brave/Chromium/Vivaldi/Opera 的 Cache/cache_data、Code Cache/js/wasm、GPUCache，并验证缓存成员命名与二进制格式 | 禁止History、Cookies、Login Data、Local Storage、IndexedDB、Session Storage、Network、Service Worker等；目录含混合名称不接纳 |
| appcache | 应用页面缓存 | 已知Electron/Chromium应用位置的上述缓存子目录，同样验证格式 | 禁止聊天附件、草稿、账号、设置、离线资源和完整用户资料目录 |
| cache | 开发工具独立卡片 | .gradle/caches、npm-cache/_cacache的合格末级缓存 | 不处理整个.android/.vscode/.gradle、项目、密钥、环境或用户配置 |

缓存识别是维护的明确规则表，未命中的缓存不要猜测加入。新增规则必须提供实际目录/格式证据和正反例测试。分类名字及短句固定，软件名来自元数据或已知映射。

末级目录只有全部成员合格、完整扫描、无链接、非空时才产生一个目标。父目录、父目录直属文件不会因选择子目录被自动处理。低于10 MB的目标不独立展示；目录中更小的成员仍完整保留。

## 谁在占用空间

### apps：常用软件占用大户

聊天社交、浏览器、办公与协作、邮箱、媒体播放、游戏与启动器、日常剪辑/创作、普通桌面工具。微信、飞书、豆包、WorkBuddy、WPS、Chrome、原神、剪映等属于这里。通过安装登记或已维护的产品映射确认归属；Steam 目录额外核实 steam.exe 产品信息与 steamapps，再归入游戏库，不因名字英文或使用者不熟悉而塞到其他。

### personal：个人文件与资产

实际Known Folders：桌面、下载、文档、图片、视频、音乐；明确的项目、源码、素材、照片及个人保存目录。重定向到其他盘时用真实位置。独立的 BaiduNetdiskDownload、LeStoreDownload、QLDownload、rrdownload、安装包容器归个人下载资产；其中明确的单个安装文件仍可单独进入清理推荐，禁止把整个下载目录当废料。资产不是软件，不提供卸载，不自动加垃圾名单。项目里出现一个软件名字不代表整个项目都属于该软件。

### devTools：其他（显示名固定为“其他”）

必须使用以下一项 subtype，不允许空值或任意新类型：

1. **development：开发工具与环境。** VS Code、Visual Studio、JetBrains、Android Studio、SDK、Gradle/npm/pnpm/Yarn、Python/Conda、Node、NuGet、Cargo/Rust等工具、依赖仓库、环境。保留项目和配置；缓存仅明确子目录可进清理区。
2. **virtual：模拟器与虚拟环境。** Android AVD、手游模拟器、WSL、Docker、VMware、VirtualBox的镜像、虚拟磁盘、快照。不是普通缓存，使用对应管理器整理，不物理强删。
3. **professional：专业工具。** CAD/CAE、MATLAB、SolidWorks、Blender、专业Adobe套件、DaVinci及专用行业工具。按所属软件聚合；工程、作品和素材归personal，不能连同软件一起误算为垃圾。
4. **component：驱动与共享组件。** NVIDIA/AMD/Intel驱动、Visual C++/.NET/WebView运行库等。显示保护状态，canUninstall=false，不产生物理删除卡片；Windows内部目录不展开成排行榜。
5. **unknown：归属待确认。** 已扫描但无法依据登记或元数据确认用途的残留目录。标题保留原名并加“归属待确认”，不猜软件名，不允许卸载或整目录加入垃圾车。后续有证据时重新分类。

**不允许放入“其他”的例子：** 微信聊天占用、Chrome资料、原神、WPS、WorkBuddy、桌面文件、下载文件、文档、代码项目、个人素材。已知软件不因为缺少安装位置或卸载登记就变为unknown；常用第三方软件保留待卸载入口，登记未唯一确认时改走系统已安装应用。组件、未知目录与个人资产仍不提供卸载。

归属规则：官方安装位置精确匹配优先，接着产品映射；登记为盘根、Apps、Program Files、ProgramData、用户主目录或 AppData 根容器的位置无效，不能把整个容器归给某款软件；专业/开发/组件语义决定明确子类型；个人目录独立识别。个人目录中的项目即使叫 Python、Chrome 或 Blender，仍属于个人资产，不按名称抢占；已知微信接收目录是明确的软件资料例外。Android Studio 属于开发工具，安卓模拟器镜像才属于 virtual。未知聚合保留目录名称和精确归属路径。未知目录不能假装覆盖所有漏扫空间。
