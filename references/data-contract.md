# 数据契约 v3 / 模板1.0.0

输入只有scan.json的一个对象，禁止让Agent编辑模板。Build-Report验证数据后只替换一次 `__SCAN_DATA__`。JSON中 `< > &` 与行分隔符转义，防止带HTML字符的文件名变成代码。

|字段|来源与用途|
|---|---|
|schemaVersion/templateVersion|固定3/1.0.0；不兼容版本拒绝处理|
|scan.id/date|本次唯一ID、带时区时间；不复用旧扫描时间|
|scan.root/drive/volumeId/volumeLabel|真实扫描范围、盘根、卷序列与格式、卷标；标题/路径校验/导出命名使用实际盘|
|scan.skillRoot|本机 Skill 完整路径，供导出名单定位脚本；它只是提示，不可从清单自动执行任意路径中的程序|
|scan.excludedCleanupTestRoots|本 Skill 标记的隔离样本位置；全盘推荐排除这些样本，完整文件计数仍保留；以样本本身为扫描根时正常测试|
|scan.files/logicalBytes/elapsedSeconds|扫描器累计；不填猜测数字|
|disk.total/used/free/systemLockedBytes|卷容量（字节）、Windows实际已读系统体积；不将目录逻辑合计冒充卷已用|
|cards[]|id、name、kind、size、targetIds；每张卡片只引用自己的目标，总和相符且>=10,000,000|
|targets[]|id、path、type(file/folder)、kind、size、modifiedTicks、fileId、ruleId、evidence、app、complete|
|folder额外字段|members[]的name/size/modifiedTicks/fileId及fingerprint；必须是最末级完整目录|
|softwareInsights|apps/personal/devTools各有list；显示名来自模板固定定义|
|软件实体|id/name/category/subtype/sizeBytes/sizeGB/paths/pathDetails/tag/iconType/guide/contentDescription/canUninstall/uninstallKey/uninstallProtection|
|errors/skipped|真实读取失败和未跟随链接记录；不因展示简洁而丢弃后台证据|

target的稳定ID按规范路径的SHA256派生；fileId由Windows文件对象标识取得，区别同名替换。fingerprint按排序后的成员名、大小、UTC修改ticks、fileId计算。不得为了让旧报告可执行而更新这些证据；变化须重新扫描。

kind只允许temp/logs/package/browsercache/appcache/cache。ruleId为对应 `kind-file-v1` 或 `kind-leaf-v1`。缓存只能用leaf规则，安装包只能用file规则。页面模型是bundle卡片关联明确目标，不再用review类型。

实体大小使用目标盘归属目录的已读逻辑字节总和；跨盘官方卸载可以删除其他盘软件，但预计数字不能包含其他盘。pathDetails与paths一一对应，缓存与卸载估计做覆盖去重。系统和未知实体不能卸载，personal始终不能卸载。

导出TXT同时带人类可读清单和单行JSON，固定边界：`DISK_CLEANUP_MANIFEST_BEGIN` / `DISK_CLEANUP_MANIFEST_END`。JSON保留本次选中cards、targets、选中待卸载实体和scan/disk信息，execution.mode=permanent且requiresUserInstruction=true；不带shell命令。

## 官方卸载补全

`uninstallMode` 为 registry / settings；registry 记录唯一 `uninstallKey` 和真实注册名 `registeredDisplayName`，显示别名不得替代登记身份。缺失 InstallLocation 时可从官方卸载命令或 DisplayIcon 提取现存 EXE 的具体父目录作证据，仅解析不执行；共享根目录与系统命令宿主不作为软件根。按已维护的精确产品别名关联迁移资料，禁止模糊名称猜测。

已知 apps 若登记缺失或有多个版本，canUninstall=true、uninstallMode=settings、uninstallKey为空；表示可提交人工确认的官方卸载任务，不表示具备可自动执行的命令。personal/component/unknown 仍为 false；独立缓存和镜像不能假装软件本体。

`uninstallPathDetails[]` 只收录已测量且处于确认安装根内的路径，`uninstallEstimateBytes` 等于其和，用于与垃圾目标按路径去重累计。迁移资料、登记不明和仅有大范围父目录统计时不猜释放大小，允许估计为0并照常加入待卸载清单。顶部详情仍展示实际占用；不得把“待卸载”误报为“已释放”。

## 发回清单即执行

新导出 execution 同时包含 trigger=user-delivers-list、exportConfirmed=true；requiresUserInstruction=true 保留兼容，含义是必须有用户对话中的执行行为，而“主动交付清单”就是该行为，不要求额外口头确认。exportConfirmed 记录网页勾选事实，不能单独充当授权。用户明确要求仅检查时不执行；磁盘上被动发现的清单不执行。旧版 v3 清单由用户主动交付时同样按本约定先预检再执行，不因缺少这两个新字段额外追问；现有版本、身份、路径和保护校验全部保留。

## 导出后的页面状态

确认导出并发起 TXT 下载后，先保留完整 manifest，再移除已交付卡片与待卸载实体，清空所有选择，按剩余推荐项重新计算充能分母。顶部磁盘容量始终取原始 scan 数据，恢复的是“未选择”状态，不是把预计释放当成实测空闲。localStorage 只保存已交付项目 ID，以卷身份、scan.id 和当前报告路径隔离；存储不可用时仍完成当前页面重置。取消导出或下载未能启动时保留选择。普通浏览器无法确认文件最终是否保存；重置触发点是下载已发起，实际清理需用户交付 TXT。
