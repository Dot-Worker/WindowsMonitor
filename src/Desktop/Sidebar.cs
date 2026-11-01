using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace WindowsMonitor {
    internal sealed class SidebarButton : Button {
        readonly int icon;
        internal bool Active;
        internal SidebarButton(int id) {
            icon=id; FlatStyle=FlatStyle.Flat; FlatAppearance.BorderSize=0; Cursor=Cursors.Hand; Height=34; Width=164;
            BackColor=Color.FromArgb(236,239,248);
        }
        protected override void OnPaint(PaintEventArgs e) {
            var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;g.Clear(BackColor);
            var ink=Active?Color.FromArgb(44,66,144):Color.FromArgb(55,66,86);
            if(Active || ClientRectangle.Contains(PointToClient(Cursor.Position))) {
                using(var path=new GraphicsPath()){
                    int w=Width-2,h=Height-2,d=12;
                    path.AddArc(1,1,d,d,180,90);path.AddArc(w-d,1,d,d,270,90);
                    path.AddArc(w-d,h-d,d,d,0,90);path.AddArc(1,h-d,d,d,90,90);path.CloseFigure();
                    using(var fill=new SolidBrush(Active?Color.FromArgb(212,222,248):Color.FromArgb(227,232,243)))g.FillPath(fill,path);
                }
            }
            float s=Height/34f;
            var saved=g.Save();g.ScaleTransform(s,s);
            using(var p=new Pen(ink,1.65f)){
                if(icon==0){for(int i=0;i<4;i++)g.DrawRectangle(p,12+(i%2)*8,10+(i/2)*8,5,5);}
                else if(icon==1){g.DrawRectangle(p,11,10,15,11);g.DrawLine(p,15,24,22,24);}
                else if(icon==2){g.DrawEllipse(p,11,9,15,15);g.DrawEllipse(p,15,9,7,15);g.DrawLine(p,11,16,26,16);}
                else if(icon==3){g.DrawRectangle(p,13,11,11,11);for(int i=0;i<3;i++){g.DrawLine(p,10,13+i*3,13,13+i*3);g.DrawLine(p,24,13+i*3,27,13+i*3);}}
                else if(icon==4){g.DrawPolygon(p,new[]{new Point(11,12),new Point(17,12),new Point(19,14),new Point(26,14),new Point(26,23),new Point(11,23)});}
                else{g.DrawEllipse(p,11,9,15,15);g.DrawLine(p,18,13,18,18);g.DrawLine(p,18,20,18,21);}
            }
            g.Restore(saved);
            TextRenderer.DrawText(g,Text,Font,new Rectangle((int)(35*s),0,Width-(int)(38*s),Height),ink,
                TextFormatFlags.VerticalCenter|TextFormatFlags.Left|TextFormatFlags.EndEllipsis);
            if(Focused && ShowFocusCues)ControlPaint.DrawFocusRectangle(g,new Rectangle(2,2,Width-5,Height-5));
        }
    }
}
