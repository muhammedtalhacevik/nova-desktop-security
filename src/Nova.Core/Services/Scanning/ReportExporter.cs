using System.Net;
using System.Text;
using Nova.Core.Models;

namespace Nova.Core.Services.Scanning;

public static class ReportExporter
{
    public static string DefaultFileName(ScanSession s) => $"Nova-Tarama-Raporu-{s.StartedAt:yyyyMMdd-HHmm}.html";

    public static string ToHtml(ScanSession s)
    {
        static string E(string? v) => WebUtility.HtmlEncode(v ?? "");
        var sb = new StringBuilder();
        var clean = s.Threats.Count == 0;
        sb.Append($$"""
            <!doctype html>
            <html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Nova Tarama Raporu</title>
            <style>
              body{margin:0;font-family:Poppins,Segoe UI,-apple-system,sans-serif;background:linear-gradient(180deg,#0B1430,#1B2F6E);color:#fff;min-height:100vh}
              .wrap{max-width:960px;margin:0 auto;padding:40px 24px}
              h1{font-size:28px;margin:0 0 4px} .muted{color:#A3ADC2}
              .card{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.09);border-radius:20px;padding:24px;margin-top:20px}
              .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
              .stat b{display:block;font-size:22px} .stat span{color:#A3ADC2;font-size:13px}
              .badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:600;font-size:13px}
              .ok{background:#16352A;color:#4ADE80} .bad{background:#3A1A22;color:#F87171}
              table{width:100%;border-collapse:collapse;font-size:14px} th,td{text-align:left;padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}
              th{color:#7C879F;font-size:12px;text-transform:uppercase;letter-spacing:.08em} td.path{word-break:break-all;color:#A3ADC2}
              footer{margin-top:32px;color:#6E7A96;font-size:12px}
            </style></head><body><div class="wrap">
            <h1>Nova Desktop Security — Tarama Raporu</h1>
            <div class="muted">{{E(s.Type.ToTurkish())}} · {{s.StartedAt:dd.MM.yyyy HH:mm:ss}} · {{E(Environment.MachineName)}}</div>
            <div class="card"><span class="badge {{(clean ? "ok" : "bad")}}">{{(clean ? "Tehdit bulunamadı" : $"{s.Threats.Count} tehdit bulundu")}}</span>
            <div class="grid" style="margin-top:20px">
              <div class="stat"><b>{{s.FilesScanned:N0}}</b><span>Taranan dosya</span></div>
              <div class="stat"><b>{{s.Threats.Count}}</b><span>Tehdit</span></div>
              <div class="stat"><b>{{s.Duration:hh\:mm\:ss}}</b><span>Süre</span></div>
              <div class="stat"><b>{{E(s.Status.ToTurkish())}}</b><span>Durum</span></div>
            </div></div>
            """);

        if (!clean)
        {
            sb.Append("<div class=\"card\"><table><tr><th>Tehdit</th><th>Dosya</th><th>Önem</th><th>Motor</th><th>İşlem</th></tr>");
            foreach (var t in s.Threats)
                sb.Append($"<tr><td><b>{E(t.ThreatName)}</b><br><span class=\"muted\">{E(t.Description)}</span></td><td class=\"path\">{E(t.FilePath)}</td><td>{E(t.Severity.ToTurkish())}</td><td>{E(t.Engine)}</td><td>{E(t.Action.ToTurkish())}</td></tr>");
            sb.Append("</table></div>");
        }

        sb.Append("<div class=\"card\"><b>Taranan konumlar</b><ul class=\"muted\">");
        foreach (var target in s.Targets) sb.Append($"<li>{E(target)}</li>");
        sb.Append("</ul></div>");
        sb.Append($"<footer>Oluşturulma: {DateTimeOffset.Now:dd.MM.yyyy HH:mm} · Nova Desktop Security</footer></div></body></html>");
        return sb.ToString();
    }

    public static string ToText(ScanSession s)
    {
        var sb = new StringBuilder();
        sb.AppendLine("NOVA DESKTOP SECURITY - TARAMA RAPORU");
        sb.AppendLine($"Tür: {s.Type.ToTurkish()}  Başlangıç: {s.StartedAt:dd.MM.yyyy HH:mm:ss}  Süre: {s.Duration:hh\\:mm\\:ss}");
        sb.AppendLine($"Taranan dosya: {s.FilesScanned:N0}  Tehdit: {s.Threats.Count}  Durum: {s.Status.ToTurkish()}");
        sb.AppendLine();
        foreach (var t in s.Threats)
            sb.AppendLine($"[{t.Severity.ToTurkish()}] {t.ThreatName} - {t.FilePath} ({t.Action.ToTurkish()})");
        return sb.ToString();
    }
}
