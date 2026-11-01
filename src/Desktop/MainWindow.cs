using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsMonitor {
    internal sealed class MainWindow : Form {
        static readonly Color Ink = Color.FromArgb(30,39,60), Muted = Color.FromArgb(83,96,120), Blue = Color.FromArgb(65,86,169);
        static readonly Color Sidebar = Color.FromArgb(236,239,248);
        static readonly string[] Jobs = {"settings","processes","files"};
        static readonly string[] JobLabels = {"系统与启动项","进程与模块","系统文件"};
        readonly MonitorHost host;
        readonly Label status = new Label(), subtitle = new Label(), feedback = new Label(), count = new Label();
        readonly ListView list = new ListView();
        readonly TextBox detail = new TextBox(), search = new TextBox();
        static readonly string[] Sections={"全部项目","系统与启动项","浏览器","进程与模块","系统文件","读取缺口"};
        readonly SidebarButton[] nav = new SidebarButton[Sections.Length];
        readonly Label evidenceGrade = new Label(), evidenceTitle = new Label(), evidenceReason = new Label();
        List<Finding> visible = new List<Finding>();
        readonly Button[] grades = new Button[4], scans = new Button[3];
        readonly Button start = new Button(), stop = new Button();
        readonly Dictionary<string, List<Finding>> rows = new Dictionary<string,List<Finding>>();
        readonly Dictionary<string, DateTime> stamps = new Dictionary<string,DateTime>();
        readonly string[] reportTimes = new string[3];
        readonly Timer timer = new Timer();
        readonly HashSet<string> manual = new HashSet<string>();
        int grade = -1, view;
        bool refreshing;

        [STAThread]
        static int Main(string[] args) {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try {
                if (args.Length != 4) throw new ArgumentException("请从 WindowsMonitor.exe 打开监控中心。");
                Application.Run(new MainWindow(new MonitorHost(args[0],args[1],args[2]), args[3]));
                return 0;
            } catch (Exception e) { MessageBox.Show(e.Message,"WindowsMonitor",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1; }
        }
        static Label TextLabel(string text, float size, Color color, bool bold) {
            return new Label { Text=text, AutoSize=true, ForeColor=color, BackColor=Color.Transparent,
                Font=new Font("Microsoft YaHei UI",size,bold ? FontStyle.Bold : FontStyle.Regular) };
        }
        static void Style(Button b, string text, Color bg, Color fg) {
            b.Text=text; b.BackColor=bg; b.ForeColor=fg; b.FlatStyle=FlatStyle.Flat;
            b.FlatAppearance.BorderSize=0; b.Cursor=Cursors.Hand; b.Height=34;
        }
        void Notice(string message) { feedback.Text = message; }
        void Attempt(Func<string> action) { try { Notice(action()); } catch(Exception e) { Notice(e.Message); } }
        MainWindow(MonitorHost h, string version) {
            host=h; Text="WindowsMonitor · 本机监控中心"; Font=new Font("Microsoft YaHei UI",9F);
            StartPosition=FormStartPosition.CenterScreen; ClientSize=new Size(1200,735); MinimumSize=new Size(980,660);
            if (Environment.GetEnvironmentVariable("WM_DESKTOP_TEST_STATE")==host.State) {
                StartPosition=FormStartPosition.Manual; Location=new Point(-20000,-20000);
            }
            AutoScaleMode=AutoScaleMode.Dpi; BackColor=Color.FromArgb(249,250,253);
            var layout = new TableLayoutPanel { Dock=DockStyle.Fill, ColumnCount=2, RowCount=1, Margin=Padding.Empty };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,200)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            Controls.Add(layout);
            var side = new FlowLayoutPanel {Dock=DockStyle.Fill, Margin=Padding.Empty, Padding=new Padding(18,28,12,12),
                FlowDirection=FlowDirection.TopDown, WrapContents=false, BackColor=Sidebar, AutoScroll=true};
            layout.Controls.Add(side,0,0);
            side.Controls.Add(TextLabel("WindowsMonitor",12,Ink,true));
            side.Controls.Add(TextLabel("本机监控   /   v"+version,9,Muted,false));
            var group=TextLabel("资源库",9,Muted,true);group.Margin=new Padding(3,22,0,6);side.Controls.Add(group);
            for(int i=0;i<nav.Length;i++){
                int k=i;var b=nav[i]=new SidebarButton(i){Text=Sections[i],Active=i==0,Margin=new Padding(2,0,0,0)};
                b.Click+=(s,e)=>{view=k;grade=-1;Render();};side.Controls.Add(b);
            }
            var section=TextLabel("手动扫描",9,Muted,true); section.Margin=new Padding(3,18,0,6); side.Controls.Add(section);
            for(int i=0;i<Jobs.Length;i++) {
                string job=Jobs[i]; var b=scans[i]=new Button {Width=164,Margin=new Padding(2,3,0,3)};
                Style(b,"扫描"+JobLabels[i],Color.White,Blue);
                b.Click+=async (s,e)=>await ManualScan(job); side.Controls.Add(b);
            }
            var continuous=TextLabel("后台",9,Muted,true); continuous.Margin=new Padding(3,18,0,6);side.Controls.Add(continuous);
            Style(start,"启动持续监控",Blue,Color.White);StyleSide(start,side);start.Click+=(s,e)=>Attempt(host.StartWatch);
            Style(stop,"停止持续监控",Color.White,Muted);StyleSide(stop,side);stop.Click+=(s,e)=>Attempt(host.StopWatch);
            var automatic = new CheckBox { AutoSize=true, ForeColor=Ink, Text="打开后自动监控",
                Checked=h.AutoStart, Margin=new Padding(3,12,0,8), AccessibleName="打开后自动监控" };
            side.Controls.Add(automatic);
            automatic.CheckedChanged+=(s,e)=>Attempt(()=>{host.AutoStart=automatic.Checked;return automatic.Checked ?
                host.StartWatch() : "下次打开时使用手动模式。";});
            var open=new Button {Width=164,Margin=new Padding(2,12,0,3)};Style(open,"打开报告目录",Sidebar,Blue);
            open.Click+=(s,e)=>Attempt(()=>{Process.Start("explorer.exe","\""+host.State+"\"");return "已打开本机报告目录。";});side.Controls.Add(open);

            var body=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(22,16,22,12),ColumnCount=1,RowCount=7};
            layout.Controls.Add(body,1,0);
            foreach(int height in new[]{48,28,56,41}) body.RowStyles.Add(new RowStyle(SizeType.Absolute,height));
            body.RowStyles.Add(new RowStyle(SizeType.Percent,100));body.RowStyles.Add(new RowStyle(SizeType.Absolute,22));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute,30));
            var top=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,Margin=Padding.Empty};
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,55));top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,45));
            var heading=TextLabel("监控总览",21,Ink,true); top.Controls.Add(heading);
            status.Dock=DockStyle.Fill;status.ForeColor=Color.FromArgb(22,108,84);status.TextAlign=ContentAlignment.MiddleRight;top.Controls.Add(status);body.Controls.Add(top,0,0);
            subtitle.Dock=DockStyle.Fill;subtitle.ForeColor=Muted;subtitle.AutoEllipsis=true;body.Controls.Add(subtitle,0,1);
            var cards=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=4,Margin=Padding.Empty};
            for(int i=0;i<4;i++){
                int k=i;cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,25));var b=grades[i]=new Button {Dock=DockStyle.Fill,Margin=new Padding(2,2,4,7)};
                Style(b,Finding.Labels[i],Finding.Tints[i],Finding.Colors[i]);b.Click+=(s,e)=>{grade=grade==k?-1:k;Render();};cards.Controls.Add(b);
            }
            body.Controls.Add(cards,0,2);
            var filters=new FlowLayoutPanel {Dock=DockStyle.Fill,WrapContents=false,Margin=Padding.Empty};
            var searchLabel=TextLabel("搜索项目",9,Muted,false); searchLabel.Margin=new Padding(3,6,6,0);
            filters.Controls.Add(searchLabel);search.Width=245;search.AccessibleName="搜索项目或来源";
            search.TextChanged+=(s,e)=>Render();filters.Controls.Add(search);
            var clear=new Button {AutoSize=true};Style(clear,"清除筛选",Color.White,Muted);clear.Height=26;
            clear.Click+=(s,e)=>{grade=-1;search.Clear();Render();};filters.Controls.Add(clear);body.Controls.Add(filters,0,3);
            var split=new SplitContainer {Dock=DockStyle.Fill,Orientation=Orientation.Vertical,Size=new Size(940,430),
                SplitterWidth=5,SplitterDistance=540,Panel1MinSize=270,Panel2MinSize=245,BackColor=Color.FromArgb(229,232,240)};
            list.Dock=DockStyle.Fill;list.View=View.Details;list.FullRowSelect=true;list.MultiSelect=false;list.HideSelection=false;list.VirtualMode=true;
            list.BorderStyle=BorderStyle.None;list.AccessibleName="风险分级项目";list.Columns.Add("等级",72);list.Columns.Add("项目",270);list.Columns.Add("来源",85);
            list.SmallImageList=new ImageList {ImageSize=new Size(1,27)};
            list.RetrieveVirtualItem+=(s,e)=>{if(e.ItemIndex<0||e.ItemIndex>=visible.Count){e.Item=new ListViewItem("");return;}
                var f=visible[e.ItemIndex];int k=(int)f.Grade;
                var item=new ListViewItem(new[]{Finding.Labels[k],f.Title,f.Source}){UseItemStyleForSubItems=false};
                item.SubItems[0].ForeColor=Finding.Colors[k];item.SubItems[0].BackColor=Finding.Tints[k];e.Item=item;};
            list.SizeChanged+=(s,e)=>list.Columns[1].Width=Math.Max(135,list.ClientSize.Width-180);
            list.SelectedIndexChanged+=(s,e)=>Describe();split.Panel1.Controls.Add(list);
            var inspect=new TableLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(14),ColumnCount=1,RowCount=5,BackColor=Color.White};
            foreach(int px in new[]{28,28,60,76})inspect.RowStyles.Add(new RowStyle(SizeType.Absolute,px));
            inspect.RowStyles.Add(new RowStyle(SizeType.Percent,100));
            inspect.Controls.Add(TextLabel("项目详情",10,Muted,true),0,0);
            evidenceGrade.AutoSize=true;evidenceGrade.Padding=new Padding(5,2,5,2);inspect.Controls.Add(evidenceGrade,0,1);
            evidenceTitle.Dock=DockStyle.Fill;evidenceTitle.AutoEllipsis=true;evidenceTitle.Font=new Font(Font,FontStyle.Bold);inspect.Controls.Add(evidenceTitle,0,2);
            evidenceReason.Dock=DockStyle.Fill;evidenceReason.AutoEllipsis=true;evidenceReason.ForeColor=Muted;inspect.Controls.Add(evidenceReason,0,3);
            detail.Dock=DockStyle.Fill;detail.Multiline=true;detail.ReadOnly=true;detail.ScrollBars=ScrollBars.Vertical;detail.BorderStyle=BorderStyle.None;
            detail.BackColor=Color.White;detail.ForeColor=Ink;detail.AccessibleName="所选项目证据";inspect.Controls.Add(detail,0,4);
            split.Panel2.Controls.Add(inspect);body.Controls.Add(split,0,4);
            count.Dock=DockStyle.Fill;count.ForeColor=Muted;body.Controls.Add(count,0,5);
            feedback.Dock=DockStyle.Fill;feedback.ForeColor=Blue;feedback.AutoEllipsis=true;body.Controls.Add(feedback,0,6);
            Notice("选择项目查看证据，点击彩色等级可筛选。");
            timer.Interval=2000;timer.Tick+=async(s,e)=>await RefreshReports();
            Shown+=async(s,e)=>{if(h.AutoStart)Attempt(host.StartWatch);timer.Start();await RefreshReports();};
            FormClosed+=(s,e)=>timer.Dispose();
        }
        static void StyleSide(Button b, FlowLayoutPanel side){b.Width=164;b.Margin=new Padding(2,3,0,3);side.Controls.Add(b);}
        async Task ManualScan(string job) {
            if (!manual.Add(job)) return;
            try { Notice("正在请求扫描…"); Notice(await host.Scan(job)); }
            catch(Exception ex) { Notice(ex.Message); }
            finally { manual.Remove(job); }
        }
        async Task RefreshReports() {
            if(refreshing)return;refreshing=true;
            try {
                var watch=host.WatchInfo();
                status.Text=watch==null?"手动模式 · 后台未运行":
                    (watch.ContainsKey("elevated") && Object.Equals(watch["elevated"],true)?"管理员监控":"持续监控")+" · 运行中";
                start.Enabled=watch==null;stop.Enabled=watch!=null;
                bool changed=false;
                for(int i=0;i<Jobs.Length;i++) {
                    string job=Jobs[i], path=host.PathFor(job+".json");bool busy=host.Locked(job);
                    scans[i].Enabled=!busy&&!manual.Contains(job);scans[i].Text=busy?JobLabels[i]+" · 扫描中":"扫描"+JobLabels[i];
                    DateTime stamp=File.GetLastWriteTimeUtc(path);
                    if(stamps.ContainsKey(job)&&stamps[job]==stamp)continue;
                    if(File.Exists(path)){
                        try {
                            var result=await Task.Run(()=>{var r=Reports.Read(path);return Tuple.Create(Reports.Classify(r),Reports.Text(r,"time"));});
                            if(IsDisposed)return;
                            rows[job]=result.Item1;
                            DateTimeOffset t; reportTimes[i]=DateTimeOffset.TryParse(result.Item2,out t)?t.ToLocalTime().ToString("MM-dd HH:mm"):result.Item2;
                        } catch(Exception ex){
                            rows[job]=new List<Finding>{new Finding(Grade.Gap,"报告读取",JobLabels[i],"本轮报告无法读取",ex.Message)};
                            reportTimes[i]="读取失败";
                        }
                    } else {rows[job]=new List<Finding>();reportTimes[i]="尚未扫描";}
                    stamps[job]=stamp;changed=true;
                }
                if(changed){subtitle.Text=String.Join("     ",JobLabels.Select((s,i)=>s+"  "+reportTimes[i]));Render();}
            } catch(Exception ex){if(!IsDisposed)Notice("读取监控状态失败："+ex.Message);}
            finally{refreshing=false;}
        }
        void Render() {
            if(grades[3]==null)return;
            for(int i=0;i<nav.Length;i++){nav[i].Active=i==view;nav[i].Invalidate();}
            var source=rows.Where(p=>view==0||view==5||p.Key==(view==3?"processes":view==4?"files":"settings")).SelectMany(p=>p.Value)
                .Where(f=>view==2?(f.Source=="快捷方式"||f.Source=="浏览器扩展"||f.Source=="浏览器策略"):view!=5||f.Grade==Grade.Gap);
            string query=search.Text.Trim();
            var items=source.Where(x=>query.Length==0||(x.Title+" "+x.Reason+" "+x.Source).IndexOf(query,StringComparison.OrdinalIgnoreCase)>=0).ToList();
            for(int i=0;i<4;i++){
                grades[i].Text=Finding.Labels[i]+"   "+items.Count(x=>(int)x.Grade==i);
                grades[i].FlatAppearance.BorderColor=Finding.Colors[i];grades[i].FlatAppearance.BorderSize=grade==i?2:0;
            }
            var previous=Selection();
            list.BeginUpdate();list.SelectedIndices.Clear();
            visible=items.Where(x=>grade<0||(int)x.Grade==grade).OrderBy(x=>x.Grade).ToList();
            list.VirtualListSize=visible.Count;list.EndUpdate();list.Invalidate();
            if(visible.Count>0){
                int index=previous==null?-1:visible.FindIndex(x=>x.Title==previous.Title&&x.Source==previous.Source);
                list.SelectedIndices.Add(Math.Max(0,index));
            }
            Describe(); count.Text=Sections[view]+"   /   "+visible.Count+" 项";
        }
        Finding Selection(){
            int i=list.SelectedIndices.Count==0?-1:list.SelectedIndices[0];
            return i<0||i>=visible.Count?null:visible[i];
        }
        void Describe(){
            var f=Selection();
            if(f==null){
                bool first=reportTimes.All(t=>t=="尚未扫描");
                evidenceGrade.Text="";evidenceTitle.Text=first?"等待首次扫描":"当前条件下没有项目";
                evidenceReason.Text=first?"从左栏选择手动扫描，或打开持续监控。":"可以切换分类或清除筛选。";
                detail.Clear();return;
            }
            int k=(int)f.Grade;
            evidenceGrade.Text=Finding.Labels[k]+"   /   "+f.Source;evidenceGrade.BackColor=Finding.Tints[k];evidenceGrade.ForeColor=Finding.Colors[k];
            evidenceTitle.Text=f.Title;evidenceReason.Text=f.Reason;
            var fields=f.Evidence as IDictionary<string,object>;
            detail.Text=fields==null?Convert.ToString(f.Evidence):String.Join("\r\n\r\n",fields.Select(p=>p.Key+"\r\n"+(p.Value is string ? (string)p.Value : Reports.Json().Serialize(p.Value))));
            detail.SelectionStart=0;
        }
    }
}
