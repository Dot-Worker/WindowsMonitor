using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;
using Map = System.Collections.Generic.Dictionary<string, object>;

namespace WindowsMonitor {
    internal enum Grade { High, Review, Info, Gap }

    internal sealed class Finding {
        internal Grade Grade;
        internal string Source, Title, Reason;
        internal object Evidence;
        internal static readonly string[] Labels = { "高风险", "需核查", "一般记录", "读取缺口" };
        internal static readonly Color[] Colors = {
            Color.FromArgb(177, 46, 56), Color.FromArgb(151, 82, 9),
            Color.FromArgb(39, 89, 145), Color.FromArgb(88, 98, 110) };
        internal static readonly Color[] Tints = {
            Color.FromArgb(255, 232, 234), Color.FromArgb(255, 242, 216),
            Color.FromArgb(229, 241, 255), Color.FromArgb(235, 238, 242) };
        internal Finding(Grade grade, string source, string title, string reason, object evidence) {
            Grade = grade; Source = source; Title = title; Reason = reason; Evidence = evidence;
        }
    }

    internal static class Reports {
        internal static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 180 }; }
        internal static Map Read(string path) {
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var r = new StreamReader(f))
                return Json().Deserialize<Map>(r.ReadToEnd());
        }
        internal static object Get(Map m, string name) {
            object v; return m != null && m.TryGetValue(name, out v) ? v : null;
        }
        internal static Map Child(Map m, string k) { return Get(m, k) as Map ?? new Map(); }
        internal static string Text(Map m, string k) { return Convert.ToString(Get(m, k)); }
        static IEnumerable<Map> Rows(Map m, string k) {
            var a = Get(m, k) as System.Collections.IList;
            return a == null ? Enumerable.Empty<Map>() : a.OfType<Map>();
        }

        internal static List<Finding> Classify(Map r) {
            var all = new List<Finding>();
            var sec = Child(r, "security");
            foreach (var v in Child(sec,"bootEvidence")) {
                var data = v.Value as Map;
                string status = Text(data,"status"), desc = Text(data,"description");
                all.Add(new Finding(Grade.Info, "UEFI 启动", v.Key,
                    status.Length>0 ? status : "启动项描述："+desc, v.Value));
            }
            foreach (var e in Rows(sec, "events")) {
                string id = Text(e, "id");
                Grade g = new[]{"1116","1118","1119"}.Contains(id) ? Grade.High :
                    new[]{"1122","1124","1128","1117"}.Contains(id) ? Grade.Info : Grade.Review;
                string action=Text(Child(e,"fields"),"Action Name");
                if(id=="1117" && new[]{"Allow","None","No action"}.Contains(action,StringComparer.OrdinalIgnoreCase))g=Grade.High;
                all.Add(new Finding(g, "Defender", Text(e, "title"), "Defender 事件 " + id + " · " + Text(e, "time"), e));
            }
            foreach (var state in Child(sec, "state")) {
                string v = Convert.ToString(state.Value);
                Grade g = v == "未知" ? Grade.Gap : v == "关闭" || v == "仅审计" ? Grade.Review : Grade.Info;
                all.Add(new Finding(g, "防护配置", state.Key, "当前配置：" + v,
                    new Map {{"项目",state.Key},{"观测值",v},{"来源","Microsoft Defender 状态和首选项"}}));
            }
            foreach (var v in Rows(Child(sec,"exclusions"),"entries"))
                all.Add(new Finding(Object.Equals(Get(v,"review"),true) ? Grade.Review : Grade.Info, "扫描排除",
                    Text(v,"type")+" · "+Text(v,"value"), Text(v,"reason"), v));
            foreach (var v in Rows(Child(sec,"exclusions"),"categories"))
                if (Text(v,"visibility") != "本轮返回可见条目")
                    all.Add(new Finding(Grade.Gap, "排除项可见性", Text(v,"type"), Text(v,"visibility"), v));
            foreach (var t in Rows(sec, "recoveryTasks"))
                all.Add(new Finding(Grade.Review, "计划任务", Text(t,"task"), Text(t,"reason").Length>0 ?
                    Text(t,"reason") : "任务配置中有删除备份或关闭恢复的命令", t));
            foreach (var t in Rows(Child(sec,"taskCache"),"findings"))
                all.Add(new Finding(Object.Equals(Get(t,"highPriority"),true) ? Grade.High : Grade.Review,
                    "任务缓存", Text(t,"task"), Text(t,"descriptor")+" · "+Text(t,"apiVisibility"), t));
            foreach (var w in Rows(Child(sec,"wmiSubscriptions"),"execution"))
                all.Add(new Finding(Grade.Review, "WMI 订阅", Text(w,"consumer"),
                    "WMI 已登记触发条件与可执行消费者的绑定，执行情况需另行核对。", w));
            foreach (var w in Rows(Child(sec,"wmiSubscriptions"),"unresolved"))
                all.Add(new Finding(Grade.Gap, "WMI 引用", Text(w,"key"), Text(w,"reason"), w));
            foreach (var w in Rows(Child(sec,"wmiSubscriptions"),"registrationEvents"))
                all.Add(new Finding(Grade.Info, "WMI 登记", Text(w,"title"), "Sysmon "+Text(w,"id")+" · "+Text(w,"time"), w));
            foreach (var v in Rows(sec,"shadowChanges"))
                all.Add(new Finding(Object.Equals(Get(v,"review"),true) ? Grade.Review : Grade.Info,
                    "卷影恢复", Text(v,"key"), Text(v,"title"), v));
            foreach (var b in Rows(sec,"browserChanges"))
                all.Add(new Finding(Grade.Review, "浏览器扩展", Text(b,"key"), Text(b,"title"), b));
            foreach (var b in Rows(sec,"browserPolicies"))
                all.Add(new Finding(Grade.Review, "浏览器策略", Text(b,"browser")+" · "+Text(b,"id"),
                    "策略声明强制安装。请核对管理来源及更新位置，组织策略也可产生此记录。", b));
            foreach (var s in Rows(r,"shortcuts")) {
                string reason = Text(s,"reason");
                all.Add(new Finding(reason.Contains("网址") || reason.Contains("敏感") ? Grade.Review : Grade.Info,
                    "快捷方式", Text(s,"path"), reason, s));
            }
            var proc = Child(r, "processes");
            foreach (var m in Rows(proc, "moduleFindings")) {
                string status = Text(m,"status"), cls = Text(m,"class"), reference = Text(m,"reference");
                Grade g = reference == "与清单哈希不同" || status == "HashMismatch" || status == "NotSigned" ? Grade.Review :
                    status == "Valid" ? Grade.Info : Grade.Gap;
                all.Add(new Finding(g, "进程模块", Text(m,"path"), String.Join(" · ", new[]{cls, reference}.Where(x=>x.Length>0)), m));
            }
            foreach (var pair in Child(proc,"memory")) {
                var m = pair.Value as Map;
                string kind = Text(m,"kind");
                bool suspicious = kind.Contains("清单外") || Text(m,"protection").Equals("0x40", StringComparison.OrdinalIgnoreCase);
                all.Add(new Finding(suspicious ? Grade.Review : Grade.Info, "执行内存", pair.Key, kind, m));
            }
            foreach (var d in Rows(Child(r,"reference"), "differences"))
                all.Add(new Finding(Grade.Review, "原版清单", Text(d,"key"), Text(d,"kind"), d));
            foreach (var c in Rows(r,"changes")) {
                string scope = Text(c,"scope"), kind = Text(c,"kind");
                if (scope=="shadows") continue;
                bool persistence = scope == "services" || scope == "tasks" || scope.StartsWith("autorun/") || scope == "defender";
                if (scope=="uefi-details" || (scope=="uefi" && Text(c,"key")=="BootOrder")) persistence=true;
                all.Add(new Finding(persistence && (kind == "修改" || kind == "新增" || kind == "删除") ? Grade.Review : Grade.Info,
                    "观测变化", Text(c,"key"), scope + " · " + kind, c));
            }
            foreach (var scope in Child(r,"coverage")) {
                var errors = Child(scope.Value as Map,"errors");
                if (errors.Count > 0) all.Add(new Finding(Grade.Gap, "采集范围", scope.Key, errors.Count + " 项未能读取", errors));
            }
            return all;
        }
    }
}
