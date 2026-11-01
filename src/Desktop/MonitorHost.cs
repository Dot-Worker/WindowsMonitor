using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace WindowsMonitor {
    internal sealed class MonitorHost {
        internal readonly string State;
        readonly string executable, script;
        Process starting;
        internal MonitorHost(string state, string exe, string source) {
            State = Path.GetFullPath(state); executable = exe; script = source;
            Directory.CreateDirectory(State);
        }
        internal string PathFor(string name) { return Path.Combine(State, name); }
        internal bool AutoStart {
            get { return File.Exists(PathFor("desktop.autostart")); }
            set {
                if (value) File.WriteAllText(PathFor("desktop.autostart"), "1");
                else File.Delete(PathFor("desktop.autostart"));
            }
        }
        internal bool Locked(string job) {
            try {
                using (var f = new FileStream(PathFor(job+".lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) {
                    f.Lock(0, 1); f.Unlock(0, 1); return false;
                }
            } catch (FileNotFoundException) { return false; }
            catch (IOException e) {
                int code = e.HResult & 0xffff;
                if (code == 32 || code == 33) return true;
                throw;
            }
        }
        internal IDictionary<string,object> WatchInfo() {
            if (!Locked("watch")) return null;
            try { return Reports.Read(PathFor("watch.json")); }
            catch (FileNotFoundException) { return new Dictionary<string,object>(); }
        }
        static string Quote(string path) {
            // Windows paths cannot contain quotes. Escape trailing separators before the closing quote.
            return "\"" + path + new string('\\', path.Length - path.TrimEnd('\\').Length) + "\"";
        }
        Process Launch(string command, bool capture) {
            var info = new ProcessStartInfo(executable,
                (script.Length == 0 ? "" : "-E -S -X utf8 " + Quote(script) + " ") + command + " --state " + Quote(State));
            info.UseShellExecute = false; info.CreateNoWindow = true;
            info.RedirectStandardError = capture;
            if (capture) info.StandardErrorEncoding = System.Text.Encoding.UTF8;
            info.EnvironmentVariables["PYINSTALLER_RESET_ENVIRONMENT"] = "1";
            info.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
            return Process.Start(info);
        }
        internal string StartWatch() {
            if (Locked("watch")) return "持续监控已在运行，已连接现有后台。";
            if (starting != null && !starting.HasExited) return "正在启动持续监控…";
            if (starting != null) starting.Dispose();
            starting = Launch("watch", false);
            return "已请求启动持续监控。关闭窗口后后台仍会运行。";
        }
        internal string StopWatch() {
            if (!Locked("watch")) return "持续监控已停止。";
            File.WriteAllText(PathFor("stop.request"), "stop");
            return "已请求停止持续监控。";
        }
        internal async Task<string> Scan(string job) {
            if (Locked(job)) return "该类别已在扫描，结果将在完成后刷新。";
            var w = WatchInfo();
            if (w != null && w.ContainsKey("manualRequests") && Object.Equals(w["manualRequests"], true)) {
                File.WriteAllText(PathFor(job + ".request"), "scan");
                return "已交给当前后台扫描，将自动刷新报告。";
            }
            using (var p = Launch(job == "settings" ? "scan" : job, true)) {
                var err = await p.StandardError.ReadToEndAsync();
                await Task.Run(() => p.WaitForExit());
                return p.ExitCode == 0 ? "扫描完成，已更新本机报告。" : "扫描未完成：" + err.Trim();
            }
        }
    }
}
