using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
[assembly: System.Reflection.AssemblyVersion("1.7.4.0")]
[assembly: System.Reflection.AssemblyTitle("SnowEdge")]
[assembly: System.Reflection.AssemblyProduct("SnowEdge")]
[assembly: System.Reflection.AssemblyFileVersion("1.7.4.0")]

class Desktop : Form {
    readonly string root = AppDomain.CurrentDomain.BaseDirectory;
    readonly string runtime, stopFile, address;
    readonly WebView2 browser = new WebView2();

    readonly ToolStripLabel status = new ToolStripLabel("正在启动本地工作台…");

    Process backend;
    bool closing;
    readonly bool smoke;
    double zoom = 1;
    readonly object logLock = new object();
    readonly CancellationTokenSource cancellation = new CancellationTokenSource();

    public Desktop(bool smokeTest) {
        smoke = smokeTest;
        runtime = Path.Combine(root, ".runtime");
        Directory.CreateDirectory(runtime);
        stopFile = Path.Combine(runtime, "desktop-" + Guid.NewGuid().ToString("N") + ".stop");
        int port;
        if (!int.TryParse(Environment.GetEnvironmentVariable("DESKTOP_PORT"), out port)) port=8000;
        address="http://127.0.0.1:"+port+"/";
        Text="雪锋 SnowEdge"; Width=1440; Height=960; MinimumSize=new Size(900,650);
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        StartPosition=FormStartPosition.CenterScreen; AutoScaleMode=AutoScaleMode.Dpi;
        Font=new Font("Microsoft YaHei UI",11); BackColor=Color.White;
        browser.Dock=DockStyle.Fill;Controls.Add(browser);
        Shown+=async(s,e)=>await StartWorkspace();
        FormClosing+=OnClosing;
    }
    void Log(string message) { lock(logLock) { File.AppendAllText(Path.Combine(runtime,"desktop.log"),DateTime.Now.ToString("s")+" "+message+Environment.NewLine); } }
    async Task<bool> Healthy() {
        try {
            var req=(HttpWebRequest)WebRequest.Create(address+"api/health");req.Proxy=null;req.Timeout=1000;req.ReadWriteTimeout=1000;
            using(var response=await Task.Run(()=>req.GetResponse())) using(var reader=new StreamReader(response.GetResponseStream())) {
                string json=await reader.ReadToEndAsync();return json.Contains("\"ok\":true") && json.Contains("\"ai_provider\"");
            }
        }catch{return false;}
    }
    async Task StartWorkspace() {
        try {
            var environment=await CoreWebView2Environment.CreateAsync(null,Environment.GetEnvironmentVariable("DESKTOP_PROFILE") ?? Path.Combine(runtime,"desktop-profile"));
            if(closing)return;
            await browser.EnsureCoreWebView2Async(environment);
            browser.CoreWebView2.Settings.AreDevToolsEnabled=false;
            browser.CoreWebView2.NavigationStarting+=(s,e)=>{
                Uri uri;if(!Uri.TryCreate(e.Uri,UriKind.Absolute,out uri) || uri.GetLeftPart(UriPartial.Authority)!=address.TrimEnd('/')) e.Cancel=true;
            };
            browser.CoreWebView2.NewWindowRequested+=(s,e)=>{
                e.Handled=true;
                Uri uri;
                if(Uri.TryCreate(e.Uri,UriKind.Absolute,out uri) && (uri.Scheme=="https" || uri.Scheme=="http")) {
                    if(uri.GetLeftPart(UriPartial.Authority)==address.TrimEnd('/'))browser.CoreWebView2.Navigate(e.Uri);
                    else if(MessageBox.Show(this,"在系统浏览器中打开外部链接？\n"+uri.Host,"外部链接",MessageBoxButtons.YesNo)==DialogResult.Yes)Process.Start(new ProcessStartInfo(e.Uri){UseShellExecute=true});
                }
            };
            if(!await Healthy()) {
                if(closing)return;
                string python=Path.Combine(root,".venv","Scripts","python.exe");
                if(!File.Exists(python) || (File.Exists(Path.Combine(root,"release-manifest.json")) && !File.Exists(Path.Combine(runtime,"runtime-ready")))) {
                    Text="雪锋 SnowEdge · 正在初始化运行环境";
                    string setup=Path.Combine(root,"tools","setup-runtime.ps1");
                    if(!File.Exists(setup))throw new Exception("缺少初始化脚本，请重新解压完整发布包。");
                    var setupInfo=new ProcessStartInfo("powershell.exe","-NoProfile -ExecutionPolicy Bypass -File \""+setup+"\" -ParentId "+Process.GetCurrentProcess().Id);
                    setupInfo.WorkingDirectory=root;setupInfo.UseShellExecute=false;setupInfo.CreateNoWindow=true;
                    using(var installer=Process.Start(setupInfo)) {
                        await Task.Run(()=>installer.WaitForExit());
                        if(closing)return;
                        if(installer.ExitCode!=0)throw new Exception("运行环境初始化失败。请安装 Python 3.11 或更新版本并加入 PATH，确认网络可用后重新打开程序。");
                    }
                    Text="雪锋 SnowEdge";
                }
                var info=new ProcessStartInfo(python,"\""+Path.Combine(root,"scripts","desktop-server.py")+"\" --parent "+Process.GetCurrentProcess().Id+" --port "+new Uri(address).Port+" --stop-file \""+stopFile+"\"");
                info.WorkingDirectory=root;info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
                backend=new Process{StartInfo=info};
                backend.OutputDataReceived+=(s,e)=>{if(e.Data!=null)Log(e.Data);};backend.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)Log(e.Data);};
                backend.Start();backend.BeginOutputReadLine();backend.BeginErrorReadLine();
                bool healthy=false;
                for(int i=0;i<120;i++){
                    cancellation.Token.ThrowIfCancellationRequested();
                    if(backend.HasExited)throw new Exception("本地服务启动失败。请查看 .runtime\\desktop.log。");
                    if(await Healthy()){healthy=true;break;}await Task.Delay(500,cancellation.Token);
                }
                if(!healthy)throw new Exception("服务启动超时。请查看 .runtime\\desktop.log。");
                status.Text="本地服务 · 关闭窗口自动停止";
            } else status.Text="复用已有服务 · 关闭窗口保留运行";
            if(closing)return;
            await browser.EnsureCoreWebView2Async(environment);
            if(closing)return;
            browser.ZoomFactor=zoom;browser.CoreWebView2.Navigate(address);
            if(smoke) {
                await Task.Delay(5000);
                string title=await browser.CoreWebView2.ExecuteScriptAsync("document.title");
                Log("DESKTOP_SMOKE_READY "+title);
                if(title=="\"\"" || title=="null")Environment.ExitCode=2;
                await browser.CoreWebView2.ExecuteScriptAsync("document.getElementById('displayScale').value='1.1';document.getElementById('displayScale').dispatchEvent(new Event('change'));");
                if(await browser.CoreWebView2.ExecuteScriptAsync("document.documentElement.style.zoom")!="\"1.1\"")Environment.ExitCode=3;
                using(var file=File.Create(Path.Combine(runtime,"desktop-smoke.png")))await browser.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png,file);
                Close();
            }
        }catch(OperationCanceledException){}catch(Exception ex){
            Log(ex.ToString());Environment.ExitCode=1;
            if(!closing && !smoke)MessageBox.Show(this,ex.Message+"\n\n如提示 WebView2 不可用，请安装 Microsoft Edge WebView2 Runtime。","启动未完成",MessageBoxButtons.OK,MessageBoxIcon.Warning);
            if(!closing)Close();
        }
    }
    async void OnClosing(object sender,FormClosingEventArgs e) {
        if(closing)return;
        e.Cancel=true;closing=true;cancellation.Cancel();
        status.Text="正在结束本次后台任务…";
        if(backend!=null){
            try {
                File.WriteAllText(stopFile,"stop");
                // The owner watcher also handles a crash or forced window termination.
                bool ended=await Task.Run(()=>backend.WaitForExit(20000));
                if(!ended){status.Text="正在等待后台安全退出…";await Task.Run(()=>backend.WaitForExit());}
                Log("DESKTOP_BACKEND_STOPPED");
            }catch(Exception ex){Log(ex.Message);}
        }
        browser.Dispose();Close();
    }
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [STAThread] static void Main(string[] args) {
        bool first;
        using(var mutex=new Mutex(true,"Local\\SnowEdgeDesktop-"+AppDomain.CurrentDomain.BaseDirectory.GetHashCode(),out first)){
            if(!first){MessageBox.Show("桌面工作台已经打开，请切换到现有窗口。","安全工作台");return;}
            SetProcessDPIAware();Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Desktop(Array.IndexOf(args,"--smoke")>=0));
        }
    }
}
