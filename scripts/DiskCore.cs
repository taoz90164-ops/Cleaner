using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
namespace DiskCleanup {
 public class FileStamp { public string name; public long size; public long modifiedTicks; public string fileId; }
 public class Target { public string id,path,type,kind,ruleId,evidence,app; public long size,modifiedTicks; public string fileId,fingerprint; public bool complete=true; public List<FileStamp> members=new List<FileStamp>(); }
 public class Node { public string path; public long size; public bool complete=true,hasLink=false; public int children; public List<Target> files=new List<Target>(); }
 public class Entity { public string name,category,tag,iconType,guide,contentDescription,uninstallKey,subtype; public bool canUninstall; public Dictionary<string,long> paths=new Dictionary<string,long>(StringComparer.OrdinalIgnoreCase); public long size; }
 public class ScanResult { public List<Target> targets=new List<Target>(); public List<string> errors=new List<string>(); public List<string> skipped=new List<string>(); public List<Entity> entities=new List<Entity>(); public long files,bytes,systemBytes; }
 public class RegisteredApp { public string name,location,key,category; public bool protectedApp; }
 public static class Core {
  [StructLayout(LayoutKind.Sequential)] struct FILEINFO { public uint attrs; public System.Runtime.InteropServices.ComTypes.FILETIME created,accessed,written; public uint volume,highSize,lowSize,links,highId,lowId; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle h,out FILEINFO info);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle h,int infoClass,ref byte info,uint size);
  static string HandleId(FILEINFO f){return f.volume.ToString("X8")+":"+f.highId.ToString("X8")+f.lowId.ToString("X8");}
  static Microsoft.Win32.SafeHandles.SafeFileHandle LockFile(string path,long size,long ticks,string identity){
   if(!NoLinks(path))throw new IOException("Link in path");var h=CreateFile(path,0x80010000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
   FILEINFO f;if(h.IsInvalid||!GetFileInformationByHandle(h,out f)){h.Dispose();throw new IOException("File busy or permission denied");}
   long length=((long)f.highSize<<32)|f.lowSize,modified=((long)(uint)f.written.dwHighDateTime<<32)|(uint)f.written.dwLowDateTime;
   if((f.attrs&0x410)!=0||length!=size||DateTime.FromFileTimeUtc(modified).Ticks!=ticks||HandleId(f)!=identity){h.Dispose();throw new IOException("File changed since scan");}return h;
  }
  static void DisposeFile(Microsoft.Win32.SafeHandles.SafeFileHandle h){byte yes=1;if(!SetFileInformationByHandle(h,4,ref yes,1))throw new IOException("Delete failed: "+Marshal.GetLastWin32Error());}
  public static void DeleteExactFile(string path,long size,long ticks,string identity){using(var h=LockFile(path,size,ticks,identity))DisposeFile(h);}
  public static void DeleteExactLeaf(string path,string identity,string fingerprint){
   if(FileId(path)!=identity||Fingerprint(Members(path))!=fingerprint)throw new IOException("Directory changed since scan");
   var files=Members(path);var locks=new List<Microsoft.Win32.SafeHandles.SafeFileHandle>();
   using(var dir=CreateFile(path,0,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
    if(dir.IsInvalid)throw new IOException("Directory busy or permission denied");
    try{foreach(var f in files)locks.Add(LockFile(Path.Combine(path,f.name),f.size,f.modifiedTicks,f.fileId));
     if(Fingerprint(Members(path))!=fingerprint)throw new IOException("Directory changed during validation");
     foreach(var h in locks)DisposeFile(h);
    }finally{foreach(var h in locks)h.Dispose();}
   }
   // Non-recursive removal can never delete a concurrently added child.
   Directory.Delete(path,false);
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool GetVolumeInformation(string root,StringBuilder label,uint len,out uint serial,out uint max,out uint flags,StringBuilder fs,uint fslen);
  public static string Norm(string p){return Path.GetFullPath(p).TrimEnd('\\').ToLowerInvariant();}
  public static bool Within(string p,string root){string a=Norm(p),b=Norm(root);return a==b||a.StartsWith(b+"\\",StringComparison.OrdinalIgnoreCase);}
  public static bool IsSpecificAppLocation(string path){
   if(String.IsNullOrWhiteSpace(path))return false;
   string p=Norm(path),r=Norm(Path.GetPathRoot(path));if(p==r)return false;
   string rel=p.Substring(r.Length).TrimStart('\\');
   return !Regex.IsMatch(rel,@"^(users|program files( \(x86\))?|programdata|apps|windows)$|^users\\[^\\]+(\\appdata(\\(local|roaming|locallow))?)?$",RegexOptions.IgnoreCase);
  }
  public static string Id(string p){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(Norm(p)))).Replace("-","").Substring(0,24).ToLowerInvariant();}
  public static string Volume(string path){uint serial,max,flags;var a=new StringBuilder(256);var b=new StringBuilder(256);if(!GetVolumeInformation(Path.GetPathRoot(Path.GetFullPath(path)),a,256,out serial,out max,out flags,b,256))throw new IOException("Cannot identify target volume");return serial.ToString("X8")+":"+b;}
  public static string FileId(string path){using(var h=CreateFile(path,0,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){FILEINFO f;if(h.IsInvalid||!GetFileInformationByHandle(h,out f))throw new IOException("Cannot identify file: "+path);return f.volume.ToString("X8")+":"+f.highId.ToString("X8")+f.lowId.ToString("X8");}}
  public static bool NoLinks(string path){string p=Path.GetFullPath(path);while(p!=null){if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)return false;var d=Directory.GetParent(p);p=d==null?null:d.FullName;}return true;}
  public static bool Protected(string path){
   string p=Norm(path),r=Norm(Path.GetPathRoot(path));if(p==r)return true;
   string rel=p.Substring(r.Length).TrimStart('\\');
   if(Regex.IsMatch(rel,@"^(windows|program files( \(x86\))?|recovery|system volume information|\$recycle\.bin|boot|efi|msocache)(\\|$)",RegexOptions.IgnoreCase))return true;
   if(Regex.IsMatch(rel,@"^(users|programdata)$|^users\\[^\\]+$|^users\\[^\\]+\\(appdata(\\(local|roaming|locallow))?|desktop|documents|downloads|pictures|videos|music)$",RegexOptions.IgnoreCase))return true;
   if(Regex.IsMatch(p,@"\\(\.ssh|\.git|credentials|backups|sessions|package cache)(\\|$)",RegexOptions.IgnoreCase))return true;
   return false;
  }
  public static string Fingerprint(List<FileStamp> files){files.Sort((a,b)=>StringComparer.OrdinalIgnoreCase.Compare(a.name,b.name));var s=new StringBuilder();foreach(var f in files)s.Append(f.name.ToLowerInvariant()).Append('\0').Append(f.size).Append('\0').Append(f.modifiedTicks).Append('\0').Append(f.fileId).Append('\n');using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(s.ToString()))).Replace("-","").ToLowerInvariant();}
  public static List<FileStamp> Members(string dir){if(!NoLinks(dir))throw new IOException("Link in path");var all=new List<FileStamp>();foreach(string p in Directory.GetFileSystemEntries(dir)){var a=File.GetAttributes(p);if((a&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=0)throw new IOException("New child directory or link");var f=new FileInfo(p);all.Add(new FileStamp{name=f.Name,size=f.Length,modifiedTicks=f.LastWriteTimeUtc.Ticks,fileId=FileId(p)});}return all;}
  public static string Metadata(string path){try{var v=System.Diagnostics.FileVersionInfo.GetVersionInfo(path);return (v.ProductName+" "+v.FileDescription+" "+v.OriginalFilename).Trim();}catch{return "";}}
  static uint ReadMagic(string path){try{using(var f=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){var b=new byte[4];if(f.Read(b,0,4)!=4)return 0;return BitConverter.ToUInt32(b,0);}}catch{return 0;}}
  static bool PortableExe(string path){try{using(var f=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var r=new BinaryReader(f)){if(r.ReadUInt16()!=0x5A4D||f.Length<64)return false;f.Position=60;uint offset=r.ReadUInt32();if(offset>f.Length-4)return false;f.Position=offset;return r.ReadUInt32()==0x4550;}}catch{return false;}}
  public static string Scope(string path){
   string p=Norm(path);if(Protected(p))return "";
   if(Regex.IsMatch(p,@"\\(history|cookies|login data|local storage|indexeddb|session storage|network|service worker)(\\|$)",RegexOptions.IgnoreCase))return "";
   bool chromium=Regex.IsMatch(p,@"\\(google\\chrome|microsoft\\edge|bravesoftware\\brave-browser|chromium|vivaldi|opera software)(\\|$)",RegexOptions.IgnoreCase);
   bool app=Regex.IsMatch(p,@"\\(feishu|larkshell|doubao|workbuddy|@genieworkbuddy|codex|qoder|coze|zcode|antigravity|jianyingpro|capcut|ocs desktop)([^\\]*)(\\|$)",RegexOptions.IgnoreCase);
   if((chromium||app)&&Regex.IsMatch(p,@"\\(cache\\cache_data|code cache\\(js|wasm)|gpucache)$",RegexOptions.IgnoreCase))return chromium?"browsercache":"appcache";
   if(Regex.IsMatch(p,@"\\(\.gradle\\caches|npm-cache\\_cacache)(\\|$)",RegexOptions.IgnoreCase))return "cache";
   if(Regex.IsMatch(p,@"\\(appdata\\local\\temp|windows\\temp)(\\|$)",RegexOptions.IgnoreCase)||WithinTemp(p))return "temp";
   if(Regex.IsMatch(p,@"\\appdata\\(local|roaming)\\[^\\]+\\(logs|crashreports|crashes)(\\|$)|\\appdata\\local\\crashdumps$",RegexOptions.IgnoreCase))return "logs";
   return "";
  }
  static bool WithinTemp(string path){string t=Path.GetTempPath();return Within(path,t);}
  public static string ClassifyFile(string path,long size,long ticks,string metadata){
   if(Protected(path))return "";string p=Norm(path),ext=Path.GetExtension(p),name=Path.GetFileName(p);bool old=ticks<DateTime.UtcNow.AddDays(-7).Ticks;string scope=Scope(Path.GetDirectoryName(p));
   if(scope=="temp"&&old&&!Regex.IsMatch(name,@"recover|autosave|\.asd$|\.wbk$|\.part$|\.crdownload$",RegexOptions.IgnoreCase))return "temp";
   if(scope=="cache")return "cache";
   if(scope=="logs"&&old&&Regex.IsMatch(ext,@"^\.(log|dmp|mdmp|hdmp|etl|txt)$"))return "logs";
   if(ext==".msi"&&ReadMagic(path)==0xE011CFD0)return "package";
   bool updater=Regex.IsMatch(p,@"\\([^\\]*-updater|app_shell_cache_\d+|update\\download)(\\|$)|\\(update|selfupdate)\\",RegexOptions.IgnoreCase);
   if(ext==".exe"&&PortableExe(path)&&!Regex.IsMatch(name,@"unins|uninstall",RegexOptions.IgnoreCase)&&!Regex.IsMatch(metadata,@"redistributable|runtime|driver|驱动|运行库",RegexOptions.IgnoreCase)&&((updater&&Regex.IsMatch(name,@"setup|installer|^app_package_|^update\.exe$",RegexOptions.IgnoreCase))||Regex.IsMatch(metadata,@"installer|setup|安装程序|安装包",RegexOptions.IgnoreCase)))return "package";
   if(updater&&Regex.IsMatch(ext,@"^\.(7z|zip|nupkg)$")&&Regex.IsMatch(name,@"setup|package|^\d|full\.nupkg",RegexOptions.IgnoreCase))return "package";
   return "";
  }
  public static bool CacheFormat(string path,string kind){if(kind!="browsercache"&&kind!="appcache")return false;bool recognized=false;foreach(string p in Directory.GetFiles(path)){string n=Path.GetFileName(p);if(!Regex.IsMatch(n,@"^(index|the-real-index|data_[0-9]+|f_[0-9a-f]+|[0-9a-f]{16}_[0-9s]+)$",RegexOptions.IgnoreCase))return false;uint magic=ReadMagic(p);if(magic==0xC104CAC3||magic==0x656E7465||magic==0xF7A4EA1E||magic==0xFAF0ABCD||magic==0xB7674A53||Regex.IsMatch(n,@"^[0-9a-f]{16}_[0-9s]+$",RegexOptions.IgnoreCase)&&magic==0xF7A4EA1E)recognized=true;}return recognized;}
  static string Known(string path){string p=Norm(path);string[,] pairs={{"wechat|xwechat|weixin|wechat files|xwechat_files","微信"},{"feishu|larkshell","飞书"},{"doubao","豆包"},{"workbuddy|genieworkbuddy","WorkBuddy"},{"jianyingpro|capcut","剪映专业版"},{"genshin impact|原神","原神"},{"google\\\\chrome","谷歌浏览器"},{"microsoft\\\\edge","微软 Edge 浏览器"},{"kingsoft|wps office","WPS Office"},{"ubisoft","育碧游戏启动器"},{"qoder","Qoder"},{"codex","Codex"},{"coze","扣子 Coze"},{"zcode","ZCode"},{"antigravity","Antigravity"},{"rrclient","人人视频"},{"ocs desktop","OCS Desktop"},{"mailmaster","网易邮箱大师"}};for(int i=0;i<pairs.GetLength(0);i++)if(Regex.IsMatch(p,@"\\("+pairs[i,0]+@")(\\|$)",RegexOptions.IgnoreCase))return pairs[i,1];return "";}
  public static string AppName(string path,string metadata){string k=Known(path);if(k!="")return k;try{var v=System.Diagnostics.FileVersionInfo.GetVersionInfo(path);if(!String.IsNullOrWhiteSpace(v.ProductName))return v.ProductName.Trim();}catch{}string p=Path.GetFileName(Path.GetDirectoryName(path));return p.Length>0?p:"软件";}
  public static string OtherSubtype(string name){if(Regex.IsMatch(name,@"nvidia|\bintel\b|\bamd\b|driver|驱动|visual c\+\+|\.net|redistributable|runtime|webview2",RegexOptions.IgnoreCase))return "component";if(Regex.IsMatch(name,@"android studio|visual studio code",RegexOptions.IgnoreCase))return "development";if(Regex.IsMatch(name,@"android|avd|emulator|模拟器|bluestacks|ldplayer|雷电|mumu|wsa|docker|wsl|virtualbox|vmware",RegexOptions.IgnoreCase))return "virtual";if(Regex.IsMatch(name,@"gradle|npm|pnpm|yarn|python|anaconda|conda|nodejs|vscode|visual studio|jetbrains|android studio|unity|unreal|sdk|\.nuget|\.cargo|\.rustup",RegexOptions.IgnoreCase))return "development";if(Regex.IsMatch(name,@"autocad|matlab|solidworks|blender|adobe|photoshop|premiere|after effects|davinci",RegexOptions.IgnoreCase))return "professional";return "";}
  class Owner {public string key,root,name,category,subtype,uninstallKey; public bool canUninstall;}
  class Walker {
   public ScanResult result=new ScanResult();public string root;public Dictionary<string,string> personal;Dictionary<string,RegisteredApp> appAt=new Dictionary<string,RegisteredApp>(StringComparer.OrdinalIgnoreCase);Dictionary<string,Entity> entities=new Dictionary<string,Entity>(StringComparer.OrdinalIgnoreCase);
   public Walker(string r,List<RegisteredApp> a,Dictionary<string,string> p){root=r;personal=p;foreach(var app in a)if(IsSpecificAppLocation(app.location)){string key=Norm(app.location);if(!appAt.ContainsKey(key))appAt.Add(key,app);}}
   Owner Detect(string path,Owner inherited){
    string n=Path.GetFileName(path),p=Norm(path),rootRel=p.Substring(Norm(root).Length).TrimStart('\\');
    RegisteredApp a;if(appAt.TryGetValue(p,out a)){string sub=OtherSubtype(a.name);return new Owner{key="app:"+a.key,root=path,name=a.name,category=sub==""?"apps":"devTools",subtype=sub,uninstallKey=a.key,canUninstall=!a.protectedApp&&sub!="component"};}
    string known=Known(path);bool personalOwner=inherited!=null&&inherited.category=="personal";bool chatStore=Regex.IsMatch(n,@"^(wechat files|xwechat_files)$",RegexOptions.IgnoreCase);if(known!=""&&(!personalOwner||chatStore)&&(inherited==null||personalOwner||inherited.subtype=="unknown")){string sub=OtherSubtype(known);return new Owner{key="known:"+known,root=path,name=known,category=sub==""?"apps":"devTools",subtype=sub,canUninstall=false};}
    foreach(var entry in personal)if(p==Norm(entry.Key))return new Owner{key="personal:"+p,root=path,name=entry.Value,category="personal",subtype="asset"};
    string subtype=OtherSubtype(n);bool boundary=Regex.IsMatch(rootRel,@"^[^\\]+$|^users\\[^\\]+\\[^\\]+$|^users\\[^\\]+\\appdata\\(local|roaming|locallow)\\[^\\]+$|^program files( \(x86\))?\\[^\\]+$|^programdata\\[^\\]+$",RegexOptions.IgnoreCase);
    if(boundary&&subtype!=""&&(inherited==null||inherited.subtype=="unknown"))return new Owner{key="other:"+p,root=path,name=n,category="devTools",subtype=subtype};
    if(boundary&&Regex.IsMatch(n,@"^(desktop|documents|downloads|pictures|videos|music|projects|workspace|素材|项目|代码|笔记|资料|剪辑草稿|下载|文档|照片|视频)$",RegexOptions.IgnoreCase))return new Owner{key="personal:"+p,root=path,name=n,category="personal",subtype="asset"};
    if(boundary&&(inherited==null||inherited.subtype=="unknown")&&!Regex.IsMatch(n,@"^(users|appdata|local|roaming|locallow|program files( \(x86\))?|programdata|windows|\$recycle.bin|system volume information|recovery|boot|efi)$",RegexOptions.IgnoreCase))return new Owner{key="unknown:"+p,root=path,name=n+"（归属待确认）",category="devTools",subtype="unknown"};
    return inherited;
   }
   void Account(Owner owner,long size){if(owner==null)return;Entity e;if(!entities.TryGetValue(owner.key,out e)){e=new Entity{name=owner.name,category=owner.category,subtype=owner.subtype,uninstallKey=owner.uninstallKey,canUninstall=owner.canUninstall};e.tag=e.category=="personal"?"个人文件":e.subtype=="component"?"驱动与共享组件":e.subtype=="virtual"?"模拟器与虚拟环境":e.subtype=="development"?"开发工具与环境":e.subtype=="professional"?"专业工具":e.subtype=="unknown"?"归属尚未确认":"软件程序与使用资料";e.iconType=e.category=="personal"?"document":e.subtype=="virtual"?"mobile":e.subtype=="development"?"code":"box";e.guide=e.category=="personal"?"打开对应文件夹 → 整理重要文件 → 按需要迁移到其他盘。":e.subtype=="component"?"这是驱动或共享运行组件，保持保留；需要维护时使用 Windows 更新或设备厂商工具。":e.subtype=="unknown"?"先查看文件用途与所属软件，确认后再通过软件设置整理；不要直接整目录删除。":e.subtype=="virtual"?"打开模拟器或虚拟环境管理器 → 查看镜像、快照与磁盘 → 删除不再使用的实例。":e.subtype=="development"?"打开对应开发工具 → 查看环境、SDK 或缓存管理 → 整理不再使用的版本，保留项目与配置。":"打开软件 → 设置 → 存储或缓存管理 → 按需要整理；不再使用时可通过系统官方卸载入口移除。";e.contentDescription=e.category=="personal"?"你保存的文件、素材与项目。":e.subtype=="unknown"?"尚未确认归属的文件，需要先了解用途。":"软件程序、使用资料，以及下载或生成的资源。";entities.Add(owner.key,e);}e.size+=size;if(!e.paths.ContainsKey(owner.root))e.paths[owner.root]=0;e.paths[owner.root]+=size;}
   public Node Walk(string path,Owner inherited){
    Node node=new Node{path=path};Owner owner=Detect(path,inherited);var stamps=new List<FileStamp>();bool allTemp=true,allLogs=true,allCache=true;string scope=Scope(path);bool system=Regex.IsMatch(Norm(path),@"^[a-z]:\\windows(\\|$)");
    try{foreach(string p in Directory.EnumerateFileSystemEntries(path)){
     try{FileAttributes a=File.GetAttributes(p);if((a&FileAttributes.ReparsePoint)!=0){node.hasLink=true;result.skipped.Add(p);continue;}
      if((a&FileAttributes.Directory)!=0){node.children++;Node child=Walk(p,owner);node.size+=child.size;node.complete &= child.complete;node.hasLink |= child.hasLink;continue;}
      var f=new FileInfo(p);long size=f.Length;node.size+=size;result.bytes+=size;result.files++;if(result.files%25000==0)Console.WriteLine("Scanned "+result.files+" files; read logical size "+(result.bytes/1e9).ToString("F2")+" GB");if(system)result.systemBytes+=size;else Account(owner,size);
      string metadata=(f.Extension.Equals(".exe",StringComparison.OrdinalIgnoreCase))?Metadata(p):"";string kind=ClassifyFile(p,size,f.LastWriteTimeUtc.Ticks,metadata);allTemp &= kind=="temp";allLogs &= kind=="logs";allCache &= kind=="cache";
      bool folderCandidate=scope=="temp"||scope=="logs"||scope=="cache"||scope=="browsercache"||scope=="appcache";string identity="";if(folderCandidate||kind!="")identity=FileId(p);
      if(folderCandidate)stamps.Add(new FileStamp{name=f.Name,size=size,modifiedTicks=f.LastWriteTimeUtc.Ticks,fileId=identity});
      if(size>=10000000&&kind!=""&&kind!="cache"){node.files.Add(new Target{id=Id(p),path=p,type="file",kind=kind,ruleId=kind+"-file-v1",evidence=metadata.Length>0?metadata:"已知位置与格式规则",app=AppName(p,metadata),size=size,modifiedTicks=f.LastWriteTimeUtc.Ticks,fileId=identity});}
     }catch(Exception ex){node.complete=false;result.errors.Add(p+" : "+ex.Message);}
    }}catch(Exception ex){node.complete=false;result.errors.Add(path+" : "+ex.Message);}
    bool valid=node.children==0&&node.complete&&!node.hasLink&&node.size>0&&!Protected(path)&&stamps.Count>0;
    bool accepted=scope=="temp"&&allTemp||scope=="logs"&&allLogs||scope=="cache"&&allCache||((scope=="browsercache"||scope=="appcache")&&CacheFormatSafe(path,scope));
    if(valid&&accepted){result.targets.Add(new Target{id=Id(path),path=path,type="folder",kind=scope,ruleId=scope+"-leaf-v1",evidence="完整扫描的最末级目录；已核实分类范围",app=Known(path),size=node.size,modifiedTicks=Directory.GetLastWriteTimeUtc(path).Ticks,fileId=FileId(path),fingerprint=Fingerprint(stamps),members=stamps});}
    else result.targets.AddRange(node.files);
    return node;
   }
   bool CacheFormatSafe(string path,string scope){try{return CacheFormat(path,scope);}catch{return false;}}
   public ScanResult Run(){Walk(root,null);result.entities.AddRange(entities.Values);return result;}
  }
  public static ScanResult Scan(string root,RegisteredApp[] apps,string[] personalPaths,string[] personalNames){var p=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);for(int i=0;i<personalPaths.Length;i++)p[personalPaths[i]]=personalNames[i];return new Walker(root,new List<RegisteredApp>(apps),p).Run();}
 }
}
